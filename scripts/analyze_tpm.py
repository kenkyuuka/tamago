#!/usr/bin/env python3
"""
Generic KiriKiri XP3 encryption analyzer.

Launches a KiriKiri game under Wine with Frida, finds the .tpm decryption
plugin, and analyzes the XP3 extraction filter to extract the decryption
logic.

The approach:
  1. Launch the game + frida-server under Wine
  2. Attach Frida to the game process
  3. Find the loaded .tpm module (the decryption plugin)
  4. Hook the filter callback at runtime to observe actual decryption behavior
  5. Dump the .tpm binary and filter function for static analysis
  6. Feed test data through the filter to characterize the algorithm

Usage:
    python3 analyze_tpm.py /path/to/game.exe
    python3 analyze_tpm.py /path/to/game.exe --wait 15
"""

import subprocess
import time
import frida
import os
import sys
import signal
import json
import struct
import argparse

# --- Configuration ---
WINE_PREFIX = os.environ.get("WINEPREFIX", os.path.expanduser("~/.wine"))
FRIDA_SERVER_PATH = os.path.join(os.path.dirname(__file__), "frida-server.exe")
FRIDA_HOST = "127.0.0.1:27042"


def start_wine_processes(game_path, wait_time):
    wine_env = os.environ.copy()
    wine_env["WINEPREFIX"] = WINE_PREFIX
    wine_env["LANG"] = "ja_JP.UTF-8"

    print(f"[*] Starting Frida Server: {FRIDA_SERVER_PATH}")
    proc_frida = subprocess.Popen(
        ["wine", FRIDA_SERVER_PATH, "-l", FRIDA_HOST],
        env=wine_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print(f"[*] Launching Game: {game_path}")
    proc_game = subprocess.Popen(
        ["wine", game_path],
        env=wine_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print(f"[*] Waiting {wait_time}s for Wine to stabilize...")
    time.sleep(wait_time)
    return proc_frida, proc_game


def find_game_pid(device, process_name):
    processes = device.enumerate_processes()
    for p in processes:
        if process_name.lower() in p.name.lower():
            print(f"[+] Found process: PID {p.pid} ({p.name})")
            return p.pid
    print(f"[-] Could not find process matching '{process_name}'")
    print(f"    Available processes:")
    for p in processes:
        print(f"      PID {p.pid}: {p.name}")
    return None


def analyze(device, pid, output_dir):
    print(f"\n[*] Attaching to PID {pid}...")
    session = device.attach(pid)

    results = {
        "tpm_dump": bytearray(),
        "tpm_base": None,
        "tpm_size": None,
        "tpm_name": None,
        "filter_addr": None,
        "v2link_addr": None,
        "filter_dump": None,
        "v2link_dump": None,
        "test_results": [],
        "done": False,
    }

    # This Frida script:
    #   1. Finds the .tpm module
    #   2. Locates V2Link and the filter callback it registers
    #   3. Hooks the filter to observe decryption on real game data
    #   4. Runs test vectors through the filter
    #   5. Dumps the .tpm binary and key function bytes
    script_code = r"""
    'use strict';

    // ---- Step 1: Find the .tpm module ----
    var tpmModule = null;
    Process.enumerateModules().forEach(function(m) {
        if (m.name.toLowerCase().endsWith(".tpm")) {
            tpmModule = m;
        }
    });

    if (!tpmModule) {
        console.log("[-] No .tpm module found. This game may not use TPM-based encryption.");
        console.log("    Loaded modules:");
        Process.enumerateModules().forEach(function(m) {
            console.log("      " + m.name + " @ " + m.base);
        });
        send({"type": "no_tpm"});
    } else {
        console.log("[+] TPM module: " + tpmModule.name);
        console.log("    Base: " + tpmModule.base + "  Size: " + tpmModule.size);

        // ---- Step 2: Find V2Link export ----
        var v2linkAddr = null;
        tpmModule.enumerateExports().forEach(function(e) {
            console.log("    Export: " + e.name + " @ " + e.address);
            if (e.name === "V2Link" || e.name === "_V2Link@4") {
                v2linkAddr = e.address;
            }
        });

        if (!v2linkAddr) {
            console.log("[-] V2Link export not found in TPM!");
            send({"type": "no_v2link"});
        } else {
            console.log("[+] V2Link @ " + v2linkAddr);

            // ---- Step 3: Find the filter callback address ----
            // V2Link typically resolves TVPSetXP3ArchiveExtractionFilter, then
            // pushes the filter function address and calls it.
            //
            // We scan V2Link for the pattern:  68 XX XX XX XX FF D0
            //   push imm32 (the filter addr)   call eax (the registration func)
            //
            // Or: 68 XX XX XX XX E8 XX XX XX XX (push + call rel32)
            //
            // We also look for push imm32 where the imm32 points within the TPM.

            // Follow V2Link if it's a thunk (MSVC incremental link thunk).
            // These are short stubs ending with jmp rel32 to the real function.
            var scanAddr = v2linkAddr;
            var thunkBytes = new Uint8Array(v2linkAddr.readByteArray(20));
            for (var ti = 0; ti < 16; ti++) {
                if (thunkBytes[ti] === 0xE9) {
                    var jmpRel = v2linkAddr.add(ti + 1).readS32();
                    scanAddr = v2linkAddr.add(ti + 5 + jmpRel);
                    console.log("[+] V2Link is a thunk (jmp at +" + ti + "), following to " + scanAddr);
                    break;
                } else if (thunkBytes[ti] === 0xEB) {
                    var jmpRel8 = v2linkAddr.add(ti + 1).readS8();
                    scanAddr = v2linkAddr.add(ti + 2 + jmpRel8);
                    console.log("[+] V2Link is a thunk (short jmp at +" + ti + "), following to " + scanAddr);
                    break;
                }
            }

            var v2linkBytes = scanAddr.readByteArray(512);
            var v2b = new Uint8Array(v2linkBytes);
            var tpmBase = tpmModule.base;
            var tpmEnd = tpmBase.add(tpmModule.size);
            var filterAddr = null;
            var candidates = [];

            function looksLikeString(addr) {
                var probe = new Uint8Array(addr.readByteArray(8));
                // All printable ASCII = likely a string
                var asciiCount = 0;
                for (var p = 0; p < probe.length; p++) {
                    if (probe[p] >= 0x20 && probe[p] <= 0x7e) asciiCount++;
                }
                if (asciiCount === probe.length) return true;
                // UTF-16 LE pattern: alternating printable ASCII + null bytes
                var utf16 = true;
                for (var p = 0; p < probe.length - 1; p += 2) {
                    if (!((probe[p] >= 0x20 && probe[p] <= 0x7e) && probe[p+1] === 0x00)) {
                        utf16 = false;
                        break;
                    }
                }
                return utf16;
            }

            for (var i = 0; i < v2b.length - 6; i++) {
                // Look for push imm32 (0x68)
                if (v2b[i] === 0x68) {
                    var imm = v2b[i+1] | (v2b[i+2] << 8) | (v2b[i+3] << 16) | (v2b[i+4] << 24);
                    var immPtr = ptr(imm >>> 0);

                    // Check if the pushed address is within the TPM module
                    if (immPtr.compare(tpmBase) >= 0 && immPtr.compare(tpmEnd) < 0) {
                        // Check if the next instruction is a call:
                        //   FF D0-D7 = call reg
                        //   FF 15    = call [imm32]
                        //   E8       = call rel32
                        var nextByte = v2b[i+5];
                        var isCall = false;
                        if (nextByte === 0xFF) {
                            var modrm = v2b[i+6];
                            if ((modrm >= 0xD0 && modrm <= 0xD7) || modrm === 0x15 ||
                                (modrm >= 0x10 && modrm <= 0x17)) {
                                isCall = true;
                            }
                        } else if (nextByte === 0xE8) {
                            isCall = true;
                        }

                        if (isCall) {
                            var isString = looksLikeString(immPtr);
                            console.log("[+] Candidate @ " + immPtr +
                                " (V2Link+" + i + ") " +
                                (isString ? "[DATA - skipped]" : "[CODE]"));

                            if (!isString) {
                                candidates.push(immPtr);
                            }
                        }
                    }
                }
            }

            // Use the last code candidate (filter is typically the last
            // address pushed before a call in V2Link).
            if (candidates.length > 0) {
                filterAddr = candidates[candidates.length - 1];
            }

            // Always dump V2Link for diagnostics
            console.log("\n--- V2Link bytes ---");
            console.log(hexdump(v2linkAddr, {length: 128, ansi: false}));
            if (scanAddr.compare(v2linkAddr) !== 0) {
                console.log("--- V2Link real body (after thunk) ---");
                console.log(hexdump(scanAddr, {length: 512, ansi: false}));
            }

            if (!filterAddr) {
                console.log("[!] Could not auto-detect filter address from V2Link.");
            } else {
                console.log("[+] Filter function @ " + filterAddr);

                // Dump filter function bytes
                console.log("\n--- Filter function disassembly bytes ---");
                console.log(hexdump(filterAddr, {length: 256, ansi: false}));

                // ---- Step 4: Analyze filter with test data ----
                // The filter signature is: void __stdcall filter(tTVPXP3ExtractionFilterInfo* info)
                // tTVPXP3ExtractionFilterInfo (32-bit):
                //   +0x00: DWORD SizeOfSelf    (0x18 for 32-bit)
                //   +0x04: UINT64 Offset
                //   +0x0C: void* Buffer
                //   +0x10: DWORD BufferSize
                //   +0x14: DWORD FileHash
                //
                // We allocate test structs and call the filter to see what it does.

                console.log("\n--- Running test vectors ---");
                var filterFunc = new NativeFunction(filterAddr, 'void', ['pointer'], 'stdcall');

                function readBytes(addr, len) {
                    var out = [];
                    for (var i = 0; i < len; i++) {
                        out.push(addr.add(i).readU8());
                    }
                    return out;
                }

                function bytesToHex(arr) {
                    return arr.map(function(b) {
                        return ("0" + b.toString(16)).slice(-2);
                    }).join(" ");
                }

                function zeroFill(addr, len) {
                    for (var i = 0; i < len; i++) {
                        addr.add(i).writeU8(0);
                    }
                }

                function seqFill(addr, len) {
                    for (var i = 0; i < len; i++) {
                        addr.add(i).writeU8(i & 0xFF);
                    }
                }

                // Test with several hash values and zero-filled plaintext
                // (reveals XOR key stream directly)
                var testHashes = [0x00000000, 0x00000001, 0x00000008, 0x12345678,
                                  0xDEADBEEF, 0xFFFFFFFF, 0xABCD1234];
                var testSize = 32;

                testHashes.forEach(function(hash) {
                    // Allocate info struct (0x18 bytes) + buffer
                    var info = Memory.alloc(0x18 + testSize);
                    var buffer = info.add(0x18);

                    // Fill buffer with 0x00 so XOR key stream is directly visible
                    zeroFill(buffer, testSize);

                    // Fill struct
                    info.writeU32(0x18);                    // SizeOfSelf
                    info.add(0x04).writeU32(0);             // Offset low
                    info.add(0x08).writeU32(0);             // Offset high
                    info.add(0x0C).writePointer(buffer);    // Buffer
                    info.add(0x10).writeU32(testSize);      // BufferSize
                    info.add(0x14).writeU32(hash >>> 0);    // FileHash

                    filterFunc(info);

                    var result = readBytes(buffer, testSize);

                    send({
                        "type": "test_result",
                        "hash": hash >>> 0,
                        "hash_hex": "0x" + ("00000000" + (hash >>> 0).toString(16)).slice(-8),
                        "key_stream": bytesToHex(result),
                        "first_byte": result[0],
                    });
                });

                // Test with non-zero input (sequential bytes 0x00-0xFF)
                // This detects non-XOR algorithms like bit rotation where
                // zero input is a fixed point.
                console.log("\n--- Testing with non-zero input ---");
                var nzSize = 256;
                var info = Memory.alloc(0x18 + nzSize);
                var buffer = info.add(0x18);
                seqFill(buffer, nzSize);

                info.writeU32(0x18);
                info.add(0x04).writeU32(0);
                info.add(0x08).writeU32(0);
                info.add(0x0C).writePointer(buffer);
                info.add(0x10).writeU32(nzSize);
                info.add(0x14).writeU32(0x12345678);

                filterFunc(info);

                var nzResult = readBytes(buffer, nzSize);
                // Build input->output mapping
                var mapping = [];
                for (var i = 0; i < nzSize; i++) {
                    mapping.push({"input": i, "output": nzResult[i]});
                }

                send({
                    "type": "nonzero_test",
                    "hash": 0x12345678,
                    "first_16_in": bytesToHex([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]),
                    "first_16_out": bytesToHex(nzResult.slice(0, 16)),
                    "mapping": mapping,
                });

                // Test with non-zero offset to check if offset affects the key
                console.log("\n--- Testing offset dependency ---");
                var offsets = [0, 1, 256, 4096, 0x10000];
                offsets.forEach(function(off) {
                    var info = Memory.alloc(0x18 + testSize);
                    var buffer = info.add(0x18);
                    zeroFill(buffer, testSize);

                    info.writeU32(0x18);
                    info.add(0x04).writeU32(off);
                    info.add(0x08).writeU32(0);
                    info.add(0x0C).writePointer(buffer);
                    info.add(0x10).writeU32(testSize);
                    info.add(0x14).writeU32(0x12345678);

                    filterFunc(info);

                    var result = readBytes(buffer, 8);
                    send({
                        "type": "offset_test",
                        "offset": off,
                        "first_bytes": bytesToHex(result),
                    });
                });

                // Test with 256-byte buffer to check for position-dependent keys
                console.log("\n--- Testing position dependency ---");
                var bigSize = 256;
                var info = Memory.alloc(0x18 + bigSize);
                var buffer = info.add(0x18);
                zeroFill(buffer, bigSize);

                info.writeU32(0x18);
                info.add(0x04).writeU32(0);
                info.add(0x08).writeU32(0);
                info.add(0x0C).writePointer(buffer);
                info.add(0x10).writeU32(bigSize);
                info.add(0x14).writeU32(0x12345678);

                filterFunc(info);

                var result = readBytes(buffer, bigSize);
                var allSame = true;
                for (var k = 1; k < result.length; k++) {
                    if (result[k] !== result[0]) {
                        allSame = false;
                        break;
                    }
                }

                var uniqueSet = {};
                result.forEach(function(b) { uniqueSet[b] = true; });

                send({
                    "type": "position_test",
                    "all_same": allSame,
                    "first_16_bytes": bytesToHex(result.slice(0, 16)),
                    "unique_values": Object.keys(uniqueSet).length,
                });
            }

            // Dump V2Link
            send({"type": "v2link_dump", "address": v2linkAddr.toString()},
                 v2linkAddr.readByteArray(128));

            // Dump filter if found
            if (filterAddr) {
                send({"type": "filter_dump", "address": filterAddr.toString()},
                     filterAddr.readByteArray(512));
            }
        }

        // ---- Step 5: Dump the full .tpm binary ----
        console.log("\n--- Dumping TPM module ---");
        var CHUNK = 4096;
        var offset = 0;
        while (offset < tpmModule.size) {
            var remaining = tpmModule.size - offset;
            var readSize = Math.min(CHUNK, remaining);
            try {
                send({"type": "tpm_chunk", "offset": offset},
                     tpmModule.base.add(offset).readByteArray(readSize));
            } catch(e) {}
            offset += readSize;
        }

        send({"type": "tpm_info",
              "name": tpmModule.name,
              "base": tpmModule.base.toString(),
              "size": tpmModule.size});
    }

    send({"type": "done"});
    """

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            msg_type = payload.get("type")

            if msg_type == "test_result":
                results["test_results"].append(payload)
            elif msg_type == "offset_test":
                results.setdefault("offset_tests", []).append(payload)
            elif msg_type == "position_test":
                results["position_test"] = payload
            elif msg_type == "nonzero_test":
                results["nonzero_test"] = payload
            elif msg_type == "tpm_chunk" and data:
                offset = payload["offset"]
                if len(results["tpm_dump"]) < offset + len(data):
                    results["tpm_dump"].extend(b'\x00' * (offset + len(data) - len(results["tpm_dump"])))
                results["tpm_dump"][offset : offset + len(data)] = data
            elif msg_type == "tpm_info":
                results["tpm_name"] = payload["name"]
                results["tpm_base"] = payload["base"]
                results["tpm_size"] = payload["size"]
            elif msg_type == "v2link_dump" and data:
                results["v2link_dump"] = data
                results["v2link_addr"] = payload["address"]
            elif msg_type == "filter_dump" and data:
                results["filter_dump"] = data
                results["filter_addr"] = payload["address"]
            elif msg_type in ("no_tpm", "no_v2link"):
                pass
            elif msg_type == "done":
                results["done"] = True
        elif message["type"] == "log":
            print(message["payload"])
        elif message["type"] == "error":
            print(f"[FRIDA ERROR] {message.get('description', message)}")

    script = session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    for _ in range(60):
        if results["done"]:
            break
        time.sleep(0.5)

    return results


# --- Key derivation formulas ---
# Each entry: (name, xp3file_scheme, formula)
# Covers GARbro Group A + Group B algorithms from ENCRYPTION_EXTENSION.md.
KEY_FORMULAS = [
    # Group A: simple hash shifts
    ("hash & 0xFF", "hash-xor shift=0", lambda h: h & 0xFF),
    ("(hash >> 1) & 0xFF", "hash-xor shift=1", lambda h: (h >> 1) & 0xFF),
    ("(hash >> 2) & 0xFF", "hash-xor shift=2", lambda h: (h >> 2) & 0xFF),
    ("(hash >> 3) & 0xFF", "hash-xor shift=3", lambda h: (h >> 3) & 0xFF),
    ("(hash >> 4) & 0xFF", "hash-xor shift=4", lambda h: (h >> 4) & 0xFF),
    ("(hash >> 5) & 0xFF", "hash-xor shift=5", lambda h: (h >> 5) & 0xFF),
    ("(hash >> 6) & 0xFF", "hash-xor shift=6", lambda h: (h >> 6) & 0xFF),
    ("(hash >> 7) & 0xFF", "hash-xor shift=7", lambda h: (h >> 7) & 0xFF),
    ("(hash >> 8) & 0xFF", "hash-xor shift=8", lambda h: (h >> 8) & 0xFF),
    ("(hash >> 16) & 0xFF", "hash-xor shift=16", lambda h: (h >> 16) & 0xFF),
    ("(hash >> 24) & 0xFF", "hash-xor shift=24", lambda h: (h >> 24) & 0xFF),
    # Group B: derived formulas
    ("~(hash + 1) & 0xFF", "PoringSoftCrypt", lambda h: (~(h + 1)) & 0xFF),
    ("(hash ^ 0xCD) & 0xFF", "SourireCrypt", lambda h: (h ^ 0xCD) & 0xFF),
    ("(hash ^ (hash >> 8)) & 0xFF", "HaikuoCrypt", lambda h: (h ^ (h >> 8)) & 0xFF),
    ("~(hash >> 7) & 0xFF", "FestivalCrypt", lambda h: (~(h >> 7)) & 0xFF),
    ("fold(hash ^ 0x1DDB6E7A)", "YuzuCrypt", lambda h: _yuzu_key(h)),
]


def _yuzu_key(h):
    h = h ^ 0x1DDB6E7A
    k = (h ^ (h >> 8) ^ (h >> 16) ^ (h >> 24)) & 0xFF
    return 0xD0 if k == 0 else k


def _popcount8(x):
    x = (x & 0x55) + ((x >> 1) & 0x55)
    x = (x & 0x33) + ((x >> 2) & 0x33)
    return ((x & 0xF) + ((x >> 4) & 0xF)) & 0xF


def _rot_byte_l(val, n):
    n = n % 8
    return ((val << n) | (val >> (8 - n))) & 0xFF


def _check_pinpoint(mapping):
    """Check if mapping matches PinPointCrypt (rotate left by popcount)."""
    for entry in mapping:
        inp = entry["input"]
        out = entry["output"]
        bc = _popcount8(inp)
        expected = _rot_byte_l(inp, bc) if bc > 0 else inp
        if out != expected:
            return False
    return True


def analyze_results(results):
    """Analyze Frida test results and return a structured summary.

    Returns a dict with:
        algorithm_type: "no-op" | "xor" | "non-xor" | "unknown"
        matched_formulas: list of (formula_name, scheme_name) tuples
        offset_dependent: bool or None
        position_dependent: bool or None
        is_pinpoint: bool
        xor_key_byte: int or None (from nonzero test)
        summary: one-line human-readable string
    """
    analysis = {
        "algorithm_type": "unknown",
        "matched_formulas": [],
        "offset_dependent": None,
        "position_dependent": None,
        "is_pinpoint": False,
        "xor_key_byte": None,
        "summary": "No test results available.",
    }

    test_results = results.get("test_results", [])
    nz_test = results.get("nonzero_test")
    offset_tests = results.get("offset_tests", [])
    pos_test = results.get("position_test")

    # Offset dependency
    if offset_tests:
        first_values = [t["first_bytes"] for t in offset_tests]
        analysis["offset_dependent"] = len(set(first_values)) > 1

    # Position dependency
    if pos_test:
        analysis["position_dependent"] = not pos_test["all_same"]

    # Non-zero input analysis
    nz_changed = 0
    if nz_test:
        mapping = nz_test["mapping"]
        nz_changed = sum(1 for m in mapping if m["input"] != m["output"])

        if nz_changed > 0:
            xor_vals = set()
            for m in mapping:
                xor_vals.add(m["input"] ^ m["output"])
            if len(xor_vals) == 1:
                analysis["xor_key_byte"] = xor_vals.pop()
            elif len(xor_vals) == 2 and 0 in xor_vals:
                xor_vals.discard(0)
                analysis["xor_key_byte"] = xor_vals.pop()

            if _check_pinpoint(mapping):
                analysis["is_pinpoint"] = True

    # Key derivation formula matching
    all_zero_xor = test_results and all(t["first_byte"] == 0 for t in test_results)

    if test_results:
        matched_formulas = []
        for name, scheme, func in KEY_FORMULAS:
            if all(func(t["hash"]) == t["first_byte"] for t in test_results):
                matched_formulas.append((name, scheme))
        analysis["matched_formulas"] = matched_formulas

    # Determine algorithm type and summary
    if all_zero_xor and nz_changed == 0:
        analysis["algorithm_type"] = "no-op"
        analysis["summary"] = "No encryption detected (NoCrypt)."
    elif all_zero_xor and nz_changed > 0:
        if analysis["is_pinpoint"]:
            analysis["algorithm_type"] = "non-xor"
            analysis["summary"] = "PinPointCrypt (rotate left by popcount of each byte)."
        else:
            analysis["algorithm_type"] = "non-xor"
            analysis["summary"] = "Non-XOR algorithm detected. Manual analysis required."
    elif test_results:
        if analysis["matched_formulas"]:
            name, scheme = analysis["matched_formulas"][0]
            pos = "single-byte" if pos_test and pos_test["all_same"] else "multi-byte"
            off = "offset-independent" if not analysis["offset_dependent"] else "offset-dependent"
            analysis["algorithm_type"] = "xor"
            analysis["summary"] = f"{pos} XOR, {off}: key_byte = {name} [{scheme}]"
        else:
            analysis["algorithm_type"] = "unknown"
            analysis["summary"] = "Could not auto-detect key derivation formula."
    else:
        analysis["algorithm_type"] = "unknown"
        analysis["summary"] = "No test results available."

    return analysis


def print_analysis(results, output_dir):
    analysis = analyze_results(results)

    print("\n" + "=" * 60)
    print("ANALYSIS RESULTS")
    print("=" * 60)

    if results.get("tpm_name"):
        print(f"\nTPM Plugin: {results['tpm_name']}")
        print(f"  Base address: {results['tpm_base']}")
        print(f"  Size: {results['tpm_size']} bytes")

    if results.get("filter_addr"):
        print(f"\nFilter callback: {results['filter_addr']}")

    # Print test results detail
    test_results = results.get("test_results", [])
    if test_results:
        print(f"\n--- Decryption behavior ({len(test_results)} test hashes) ---")
        print(f"{'Hash':>14s}  {'Key byte':>8s}  {'Key stream (first 8)':>24s}")
        print("-" * 50)

        for t in test_results:
            key_stream = t["key_stream"].split()
            first_byte = t["first_byte"]
            print(f"  {t['hash_hex']}  0x{first_byte:02x}      {' '.join(key_stream[:8])}")

        print("\n--- Key derivation analysis ---")
        if analysis["matched_formulas"]:
            for name, scheme in analysis["matched_formulas"]:
                print(f"  MATCH: key_byte = {name}  [{scheme}]")
        else:
            all_zero = all(t["first_byte"] == 0 for t in test_results)
            if all_zero:
                print("  All zero-input results are 0x00 (see non-zero test below).")
            else:
                print("  No known formula matched.")

    # Non-zero input test details
    nz_test = results.get("nonzero_test")
    if nz_test:
        mapping = nz_test["mapping"]
        changed = sum(1 for m in mapping if m["input"] != m["output"])
        print(f"\n--- Non-zero input test (hash=0x12345678) ---")
        print(f"  Input:  {nz_test['first_16_in']}")
        print(f"  Output: {nz_test['first_16_out']}")
        print(f"  Bytes changed: {changed}/256")

        if changed == 0:
            print("  Filter is a no-op (NoCrypt).")
        elif analysis["xor_key_byte"] is not None:
            xor_key = analysis["xor_key_byte"]
            print(f"  Uniform XOR confirmed: key=0x{xor_key:02x}")
        else:
            xor_vals = set(m["input"] ^ m["output"] for m in mapping)
            print(f"  NOT a simple XOR ({len(xor_vals)} distinct XOR values).")
            if analysis["is_pinpoint"]:
                print("  MATCH: PinPointCrypt (rotate left by popcount of each byte)")
            outputs = set(m["output"] for m in mapping)
            if len(outputs) == 256:
                print("  Mapping is a full byte permutation (bijective).")
                out_map = {m["input"]: m["output"] for m in mapping}
                is_involution = all(out_map.get(out_map[i], -1) == i for i in range(256))
                if is_involution:
                    print("  Mapping is an involution (self-inverse).")
            else:
                print(f"  Mapping produces {len(outputs)} unique output values (not bijective).")

    # Offset dependency
    offset_tests = results.get("offset_tests", [])
    if offset_tests:
        if not analysis["offset_dependent"]:
            print("\n  Offset does NOT affect the key (offset-independent).")
        else:
            print("\n  Offset DOES affect the key (offset-dependent):")
            for t in offset_tests:
                print(f"    offset={t['offset']:#x}: {t['first_bytes']}")

    # Position dependency
    pos_test = results.get("position_test")
    if pos_test:
        if not analysis["position_dependent"]:
            print(f"  All bytes use the SAME key (single-byte XOR).")
        else:
            print(f"  Key varies by position ({pos_test['unique_values']} unique values in 256 bytes).")
            print(f"  First 16 key bytes: {pos_test['first_16_bytes']}")

    # Save dumps
    if results.get("tpm_dump"):
        tpm_path = os.path.join(output_dir, "tpm_dump.bin")
        with open(tpm_path, "wb") as f:
            f.write(results["tpm_dump"])
        print(f"\n[+] TPM binary saved to: {tpm_path}")

    if results.get("filter_dump"):
        filter_path = os.path.join(output_dir, "filter_dump.bin")
        with open(filter_path, "wb") as f:
            f.write(results["filter_dump"])
        base = results["filter_addr"]
        print(f"[+] Filter function saved to: {filter_path} (base: {base})")
        print(f"    Disassemble with: ndisasm -b 32 -o {base} {filter_path}")

    if results.get("v2link_dump"):
        v2link_path = os.path.join(output_dir, "v2link_dump.bin")
        with open(v2link_path, "wb") as f:
            f.write(results["v2link_dump"])
        print(f"[+] V2Link function saved to: {v2link_path} (base: {results['v2link_addr']})")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  {analysis['summary']}")


def main():
    parser = argparse.ArgumentParser(description="Analyze KiriKiri XP3 encryption from a game's .tpm plugin")
    parser.add_argument("game_exe", help="Path to the game executable")
    parser.add_argument("--wait", type=int, default=10, help="Seconds to wait for Wine startup (default: 10)")
    parser.add_argument(
        "--output", "-o", default=None, help="Output directory for dumps (default: ./<game>_tpm_analysis)"
    )
    args = parser.parse_args()

    game_filename = os.path.basename(args.game_exe)
    if args.output is None:
        args.output = os.path.splitext(game_filename)[0] + "_tpm_analysis"
    os.makedirs(args.output, exist_ok=True)

    f_proc, g_proc = start_wine_processes(args.game_exe, args.wait)

    try:
        device_manager = frida.get_device_manager()
        device = device_manager.add_remote_device(FRIDA_HOST)

        pid = find_game_pid(device, game_filename)
        if pid is None:
            sys.exit(1)

        results = analyze(device, pid, args.output)
        print_analysis(results, args.output)

    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
    except frida.ServerNotRunningError:
        print("[-] Could not connect to Frida server. Try increasing --wait.")
    finally:
        f_proc.terminate()
        g_proc.terminate()


if __name__ == "__main__":
    main()
