#!/usr/bin/env python3
"""Automated XP3 encryption identification and verification.

Takes a game directory, runs detection methods in succession, verifies
candidates by decrypting real files, and either adds confirmed results
to the library or produces a diagnostic report for manual analysis.

Usage:
    python scripts/identify_encryption.py /path/to/game/dir
    python scripts/identify_encryption.py /path/to/game/dir --no-frida --dry-run
"""

import argparse
import hashlib
import importlib.resources
import json
import logging
import os
import re
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.detect import (
    MAGIC_SIGNATURES,
    UTILITY_TPMS,
    XP3_MAGIC,
    build_tpm_index,
    build_xp3_index,
    hash_file,
    hash_xp3_structure,
    instantiate_encryption,
    load_library,
    read_file_list,
    read_segment_raw,
    try_decrypt_segment,
)
from tamago.formats.xp3.encryption import get_encryption_schemes
from tamago.formats.xp3.encryption.hash_xor import HashXorEncryption
import tamago.formats.xp3 as _xp3_pkg

logger = logging.getLogger(__name__)

_XP3_PKG_DIR = Path(_xp3_pkg.__file__).resolve().parent


# --- Data structures ---


@dataclass
class DetectionCandidate:
    encryption: object  # XP3Encryption instance
    method: str  # "tpm", "xp3_hash", "probe", "frida"
    scheme_name: str  # e.g. "hash-xor"
    params: dict  # e.g. {"shift": 3}
    game_key: str = None  # library key, if from library lookup


@dataclass
class VerificationResult:
    candidate: DetectionCandidate
    total_checked: int = 0
    successes: int = 0
    failures: int = 0
    details: list = field(default_factory=list)  # per-file dicts

    @property
    def confirmed(self):
        return self.total_checked >= 3 and self.failures == 0


@dataclass
class IdentificationReport:
    game_dir: str
    xp3_files: list = field(default_factory=list)
    enc_tpms: list = field(default_factory=list)
    already_known: bool = False
    is_unencrypted: bool = False
    candidates_tried: list = field(default_factory=list)  # list of (DetectionCandidate, VerificationResult)
    confirmed_candidate: DetectionCandidate = None
    library_entry_added: bool = False
    frida_results: dict = None
    error: str = None


# --- Pipeline functions ---


def discover_game(game_dir):
    """Walk game_dir for .xp3 files and .tpm files.

    Returns (xp3_files, enc_tpms, util_tpms) as lists of absolute paths.
    """
    xp3_files = []
    enc_tpms = []
    util_tpms = []

    for root, dirs, files in os.walk(game_dir):
        for f in files:
            path = os.path.join(root, f)
            lower = f.lower()
            if lower.endswith(".xp3"):
                # Validate XP3 magic
                try:
                    with open(path, "rb") as fh:
                        if fh.read(11) == XP3_MAGIC:
                            xp3_files.append(path)
                        else:
                            logger.warning("Skipping %s: invalid XP3 magic", path)
                except OSError:
                    logger.warning("Could not read %s", path)
            elif lower.endswith(".tpm"):
                if lower in UTILITY_TPMS:
                    util_tpms.append(path)
                else:
                    enc_tpms.append(path)

    return sorted(xp3_files), sorted(enc_tpms), sorted(util_tpms)


def _load_unencrypted_library():
    """Load the unencrypted library TOML, returning a set of known XP3 hashes."""
    try:
        lib_file = importlib.resources.files("tamago.formats.xp3").joinpath("unencrypted_library.toml")
        text = lib_file.read_text(encoding="utf-8")
    except (FileNotFoundError, TypeError):
        return set()

    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

    data = tomllib.loads(text)
    hashes = set()
    for entry in data.get("games", {}).values():
        for h in entry.get("xp3_hashes", []):
            hashes.add(h)
    return hashes


def check_already_known(xp3_files, enc_tpms, library=None):
    """Check if the game is already in the encryption library or unencrypted library.

    Returns (game_key, entry) if found, else None.
    """
    if library is None:
        library = load_library()

    # Check TPM hashes
    tpm_index = build_tpm_index(library)
    for tpm_path in enc_tpms:
        h = hash_file(tpm_path)
        if h in tpm_index:
            return tpm_index[h]

    # Check XP3 structure hashes
    xp3_index = build_xp3_index(library)
    unenc_hashes = _load_unencrypted_library()

    for xp3_path in xp3_files:
        basename = os.path.basename(xp3_path)
        if basename.startswith("patch"):
            continue
        try:
            h = hash_xp3_structure(xp3_path)
        except Exception:
            continue
        if h in xp3_index:
            return xp3_index[h]
        if h in unenc_hashes:
            return ("unencrypted", {"encryption": "none"})

    return None


def check_unencrypted(xp3_files):
    """Return True if no files have the encrypted flag set across all archives."""
    for xp3_path in xp3_files:
        try:
            files = read_file_list(xp3_path)
            if any(info.encrypted for info in files):
                return False
        except Exception:
            continue
    return True


def verify_unencrypted(xp3_files, min_checks=3):
    """Verify that files without the encrypted flag are genuinely unencrypted.

    Reads files with known magic extensions and checks that the raw data
    (after decompression if needed) starts with the expected magic bytes.

    Returns (confirmed, checked, failed) where confirmed is True if at
    least min_checks files were verified with zero failures.
    """
    checked = 0
    failed = 0

    for xp3_path in xp3_files:
        try:
            magic_candidates = _find_magic_candidates(xp3_path)
        except Exception:
            continue

        for info, expected_magic, ext in magic_candidates:
            segment = info.segments[0]
            try:
                raw_data = read_segment_raw(xp3_path, segment)
                if segment.compressed:
                    data = zlib.decompress(raw_data)
                else:
                    data = raw_data
            except Exception:
                continue

            checked += 1
            if not _check_magic(data, ext, expected_magic):
                failed += 1

            if checked >= min_checks and failed == 0:
                return True, checked, failed

    confirmed = checked >= min_checks and failed == 0
    return confirmed, checked, failed


def _find_magic_candidates(xp3_path):
    """Find files with known magic extensions in an XP3, sorted by segment size."""
    files = read_file_list(xp3_path)
    candidates = []
    for info in files:
        if not info.segments or info.segments[0].compressed_size == 0:
            continue
        for ext, magic in MAGIC_SIGNATURES.items():
            if info.file_name.lower().endswith(ext):
                candidates.append((info, magic, ext))
                break
    # Prioritize files with the encrypted flag, then smallest segment size
    candidates.sort(key=lambda c: (not c[0].encrypted, c[0].segments[0].compressed_size))
    return candidates


def _check_magic(decrypted, ext, expected_magic):
    """Check if decrypted bytes match the expected magic for the file type."""
    if not decrypted or len(decrypted) < len(expected_magic):
        return False

    if decrypted[: len(expected_magic)] != expected_magic:
        return False

    # Additional checks for specific formats
    if ext in (".png",) and len(decrypted) >= 16:
        # Verify IHDR chunk marker at bytes 12-15
        if decrypted[12:16] != b'IHDR':
            return False

    return True


def verify_candidate(candidate, xp3_files, max_files_per_xp3=5):
    """Verify a candidate by decrypting files with known magic signatures.

    Returns a VerificationResult.
    """
    result = VerificationResult(candidate=candidate)

    for xp3_path in xp3_files:
        try:
            magic_candidates = _find_magic_candidates(xp3_path)
        except Exception as e:
            logger.warning("Could not read %s: %s", xp3_path, e)
            continue

        checked_this_xp3 = 0
        for info, expected_magic, ext in magic_candidates:
            if checked_this_xp3 >= max_files_per_xp3:
                break

            segment = info.segments[0]
            try:
                raw_data = read_segment_raw(xp3_path, segment)
                decrypted = try_decrypt_segment(candidate.encryption, raw_data, info, segment)
            except Exception:
                decrypted = None

            ok = _check_magic(decrypted, ext, expected_magic)

            if not ok:
                # The file might be genuinely unencrypted (some games mix encrypted
                # and unencrypted files, and some set the flag incorrectly).  If the
                # raw data decompresses cleanly without decryption, the file is not
                # encrypted — skip it rather than counting it as a failure.
                try:
                    if segment.compressed:
                        zlib.decompress(raw_data)
                    elif _check_magic(raw_data, ext, expected_magic):
                        pass
                    else:
                        raise ValueError("not plaintext")
                except Exception:
                    pass  # truly failed — fall through to count as failure
                else:
                    continue  # unencrypted file — skip

            detail = {
                "xp3": os.path.basename(xp3_path),
                "file": info.file_name,
                "ext": ext,
                "expected_magic": expected_magic.hex(),
                "got": decrypted[:8].hex() if decrypted and len(decrypted) >= 8 else None,
                "ok": ok,
            }
            result.details.append(detail)
            result.total_checked += 1
            if ok:
                result.successes += 1
            else:
                result.failures += 1
            checked_this_xp3 += 1

    return result


def detect_candidates(
    xp3_files, enc_tpms, library=None, use_frida=True, game_exe=None, frida_wait=15, force_probe=False
):
    """Yield DetectionCandidate objects, trying methods in order.

    If force_probe is True, the probe step will try all files with known
    magic extensions regardless of the encrypted flag (for games that
    encrypt without setting the flag).
    """
    if library is None:
        library = load_library()

    # 1. TPM hash lookup
    tpm_index = build_tpm_index(library)
    for tpm_path in enc_tpms:
        h = hash_file(tpm_path)
        if h in tpm_index:
            game_key, entry = tpm_index[h]
            enc = instantiate_encryption(entry)
            if enc:
                scheme_name = entry["encryption"]
                params = {
                    k: v for k, v in entry.items() if k not in ("title", "encryption", "tpm_hashes", "xp3_hashes")
                }
                yield DetectionCandidate(
                    encryption=enc,
                    method="tpm",
                    scheme_name=scheme_name,
                    params=params,
                    game_key=game_key,
                )

    # 2. XP3 structure hash lookup
    xp3_index = build_xp3_index(library)
    for xp3_path in xp3_files:
        basename = os.path.basename(xp3_path)
        if basename.startswith("patch"):
            continue
        try:
            h = hash_xp3_structure(xp3_path)
        except Exception:
            continue
        if h in xp3_index:
            game_key, entry = xp3_index[h]
            enc = instantiate_encryption(entry)
            if enc:
                scheme_name = entry["encryption"]
                params = {
                    k: v for k, v in entry.items() if k not in ("title", "encryption", "tpm_hashes", "xp3_hashes")
                }
                yield DetectionCandidate(
                    encryption=enc,
                    method="xp3_hash",
                    scheme_name=scheme_name,
                    params=params,
                    game_key=game_key,
                )
                return  # Only need one XP3 hash match

    # 3. Probe - try each registered scheme
    # Use the first XP3 that has encrypted files (or any XP3 if force_probe)
    probe_xp3 = None
    for xp3_path in xp3_files:
        try:
            files = read_file_list(xp3_path)
            if force_probe or any(info.encrypted for info in files):
                probe_xp3 = xp3_path
                break
        except Exception:
            continue

    if probe_xp3:
        files = read_file_list(probe_xp3)
        # Find candidate files with known magic
        magic_files = []
        for info in files:
            for ext, magic in MAGIC_SIGNATURES.items():
                if info.file_name.lower().endswith(ext) and info.segments and info.segments[0].compressed_size > 0:
                    magic_files.append((info, magic))
                    break
        if magic_files:
            magic_files.sort(key=lambda c: c[0].segments[0].compressed_size)
            info, expected_magic = magic_files[0]
            segment = info.segments[0]
            raw_data = read_segment_raw(probe_xp3, segment)

            # Try registered entry points
            schemes = get_encryption_schemes()
            for name, ep in schemes.items():
                cls = ep.load()
                try:
                    enc = cls()
                except (TypeError, ValueError):
                    continue
                result = try_decrypt_segment(enc, raw_data, info, segment)
                if result and result[: len(expected_magic)] == expected_magic:
                    yield DetectionCandidate(
                        encryption=enc,
                        method="probe",
                        scheme_name=name,
                        params={},
                    )

            # Try HashXorEncryption with shifts 0-31
            for shift in range(32):
                enc = HashXorEncryption(shift=shift)
                key_byte = (info.key >> shift) & 0xFF
                if key_byte == 0:
                    continue
                result = try_decrypt_segment(enc, raw_data, info, segment)
                if result and result[: len(expected_magic)] == expected_magic:
                    yield DetectionCandidate(
                        encryption=enc,
                        method="probe",
                        scheme_name="hash-xor",
                        params={"shift": shift},
                    )

    # 4. Frida analysis
    if not use_frida or not game_exe:
        return

    try:
        from analyze_tpm import (
            KEY_FORMULAS,
            analyze,
            analyze_results,
            print_analysis,
            start_wine_processes,
            find_game_pid,
        )
        import frida as frida_mod
    except ImportError:
        logger.warning("Frida not available; skipping Frida analysis")
        return

    game_filename = os.path.basename(game_exe)
    output_dir = os.path.splitext(game_filename)[0] + "_tpm_analysis"
    os.makedirs(output_dir, exist_ok=True)

    try:
        f_proc, g_proc = start_wine_processes(game_exe, frida_wait)
        try:
            device_manager = frida_mod.get_device_manager()
            device = device_manager.add_remote_device("127.0.0.1:27042")
            pid = find_game_pid(device, game_filename)
            if pid is None:
                return

            raw_results = analyze(device, pid, output_dir)
            analysis = analyze_results(raw_results)

            # Save dumps and print analysis regardless of candidate match
            print_analysis(raw_results, output_dir)

            yield from _frida_candidates(analysis)
        finally:
            f_proc.terminate()
            g_proc.terminate()
    except Exception as e:
        logger.warning("Frida analysis failed: %s", e)


def _frida_candidates(analysis):
    """Convert Frida analysis results to DetectionCandidates."""
    for formula_name, scheme_name in analysis.get("matched_formulas", []):
        # Parse scheme name to get encryption class + params
        if scheme_name.startswith("hash-xor shift="):
            shift = int(scheme_name.split("=")[1])
            enc = HashXorEncryption(shift=shift)
            yield DetectionCandidate(
                encryption=enc,
                method="frida",
                scheme_name="hash-xor",
                params={"shift": shift},
            )
        else:
            logger.warning(
                "Frida matched formula '%s' [%s] but no encryption class is implemented for it",
                formula_name,
                scheme_name,
            )


def _slugify(text):
    """Convert text to a URL-safe slug."""
    # Replace non-ASCII with hex hash
    try:
        text.encode("ascii")
        slug = text
    except UnicodeEncodeError:
        slug = hashlib.md5(text.encode("utf-8")).hexdigest()[:8]
        return slug

    slug = re.sub(r"[^\w\s-]", "", slug.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return slug or "unknown"


def generate_library_entry(game_dir, candidate, xp3_files, enc_tpms):
    """Generate a TOML library entry for a confirmed candidate.

    Returns (entry_key, toml_text).
    """
    dir_name = os.path.basename(os.path.normpath(game_dir))
    parent_name = os.path.basename(os.path.dirname(os.path.normpath(game_dir)))
    slug = _slugify(parent_name + "-" + dir_name) if parent_name else _slugify(dir_name)

    # Compute hashes
    tpm_hashes = []
    for tpm_path in enc_tpms:
        tpm_hashes.append((hash_file(tpm_path), os.path.basename(tpm_path)))

    xp3_hashes = []
    for xp3_path in xp3_files:
        basename = os.path.basename(xp3_path)
        if basename.startswith("patch"):
            continue
        try:
            h = hash_xp3_structure(xp3_path)
            xp3_hashes.append((h, basename))
        except Exception as e:
            logger.warning("Could not hash %s: %s", xp3_path, e)

    # Build TOML text
    entry_key = slug
    lines = [
        f"[games.{entry_key}]",
        f'title = "{dir_name}"',
        f'encryption = "{candidate.scheme_name}"',
    ]
    for k, v in candidate.params.items():
        lines.append(f"{k} = {v!r}")

    lines.append("tpm_hashes = [")
    for h, name in tpm_hashes:
        lines.append(f'    "{h}", # {name}')
    lines.append("]")

    lines.append("xp3_hashes = [")
    for h, name in xp3_hashes:
        lines.append(f'    "{h}", # {name}')
    lines.append("]")

    toml_text = "\n".join(lines)
    return entry_key, toml_text


def append_to_library(library_path, entry_key, toml_text):
    """Append a new entry to the encryption library TOML file."""
    with open(library_path, "a") as f:
        f.write("\n\n")
        f.write(toml_text)
        f.write("\n")


def find_missing_xp3_hashes(xp3_files, entry, library_path=None):
    """Find XP3 structure hashes not already present in a library entry.

    Checks both the parsed TOML entry and the raw file text (to catch
    hashes previously appended as comments).

    Returns a list of (hash, basename) for missing non-patch XP3 files.
    """
    known = set(entry.get("xp3_hashes", []))

    # Also scan the raw library file for hashes in comment lines
    if library_path:
        try:
            with open(library_path, "r") as f:
                raw_text = f.read()
            # Extract any 64-char hex strings (SHA-256 digests) from the file
            for match in re.finditer(r'"([0-9a-f]{64})"', raw_text):
                known.add(match.group(1))
        except OSError:
            pass

    missing = []
    for xp3_path in xp3_files:
        basename = os.path.basename(xp3_path)
        if basename.startswith("patch"):
            continue
        try:
            h = hash_xp3_structure(xp3_path)
        except Exception:
            continue
        if h not in known:
            missing.append((h, basename))
    return missing


def append_xp3_hashes(library_path, game_key, missing_hashes, game_dir):
    """Insert missing XP3 hashes into the existing library entry.

    If the entry already has an xp3_hashes array, the new hashes are
    inserted before its closing bracket. If it doesn't have one, an
    xp3_hashes array is added after the last key in the section.
    """
    dir_name = os.path.basename(os.path.normpath(game_dir))

    # Build the lines to insert
    new_lines = [f"    # {dir_name}"]
    for h, basename in sorted(missing_hashes, key=lambda x: x[1]):
        new_lines.append(f'    "{h}", # {basename}')

    with open(library_path, "r") as f:
        file_lines = f.readlines()

    section_header = f"[games.{game_key}]"

    # Find the section
    section_start = None
    for i, line in enumerate(file_lines):
        if line.strip() == section_header:
            section_start = i
            break

    if section_start is None:
        raise ValueError(f"Section {section_header} not found in {library_path}")

    # Find the end of this section (next section header or EOF)
    section_end = len(file_lines)
    for i in range(section_start + 1, len(file_lines)):
        if file_lines[i].strip().startswith("[games."):
            section_end = i
            break

    # Look for an existing xp3_hashes array within this section
    xp3_hashes_start = None
    xp3_hashes_end = None
    for i in range(section_start, section_end):
        stripped = file_lines[i].strip()
        if stripped.startswith("xp3_hashes"):
            xp3_hashes_start = i
        if xp3_hashes_start is not None and stripped == "]":
            xp3_hashes_end = i
            break

    insert_text = "\n".join(new_lines) + "\n"

    if xp3_hashes_end is not None:
        # Insert before the closing ]
        file_lines.insert(xp3_hashes_end, insert_text)
    else:
        # No xp3_hashes array exists — add one at the end of the section
        # Find the last non-blank line in the section
        insert_at = section_end
        for i in range(section_end - 1, section_start, -1):
            if file_lines[i].strip():
                insert_at = i + 1
                break

        array_text = "xp3_hashes = [\n" + insert_text + "]\n"
        file_lines.insert(insert_at, array_text)

    with open(library_path, "w") as f:
        f.writelines(file_lines)


def generate_failure_report(game_dir, report, output_dir):
    """Generate a failure report with diagnostics."""
    os.makedirs(output_dir, exist_ok=True)

    # report.json
    report_data = {
        "game_dir": report.game_dir,
        "xp3_files": [os.path.basename(f) for f in report.xp3_files],
        "enc_tpms": [os.path.basename(f) for f in report.enc_tpms],
        "already_known": report.already_known,
        "is_unencrypted": report.is_unencrypted,
        "candidates_tried": [],
        "error": report.error,
    }
    for cand, vr in report.candidates_tried:
        report_data["candidates_tried"].append(
            {
                "method": cand.method,
                "scheme_name": cand.scheme_name,
                "params": cand.params,
                "total_checked": vr.total_checked,
                "successes": vr.successes,
                "failures": vr.failures,
                "details": vr.details,
            }
        )

    with open(os.path.join(output_dir, "report.json"), "w") as f:
        json.dump(report_data, f, indent=2)

    # analysis.txt
    lines = [
        f"Encryption Identification Failure Report",
        f"Game directory: {game_dir}",
        f"XP3 files: {', '.join(os.path.basename(f) for f in report.xp3_files)}",
        f"Encryption TPMs: {', '.join(os.path.basename(f) for f in report.enc_tpms) or 'none'}",
        "",
    ]

    if not report.candidates_tried:
        lines.append("No candidates were found by any detection method.")
    else:
        lines.append(f"Candidates tried: {len(report.candidates_tried)}")
        for cand, vr in report.candidates_tried:
            lines.append(f"\n  Method: {cand.method}")
            lines.append(f"  Scheme: {cand.scheme_name} {cand.params}")
            lines.append(f"  Verification: {vr.successes}/{vr.total_checked} OK, {vr.failures} failures")
            for d in vr.details:
                if not d["ok"]:
                    lines.append(
                        f"    FAIL: {d['xp3']}/{d['file']} ({d['ext']}): "
                        f"expected {d['expected_magic']}, got {d['got']}"
                    )

    if report.error:
        lines.append(f"\nError: {report.error}")

    with open(os.path.join(output_dir, "analysis.txt"), "w") as f:
        f.write("\n".join(lines))
        f.write("\n")

    return output_dir


def _format_verification_line(xp3_name, details):
    """Format a per-XP3 verification summary line."""
    ok = sum(1 for d in details if d["ok"])
    total = len(details)
    ext_counts = {}
    for d in details:
        if d["ok"]:
            ext_counts[d["ext"]] = ext_counts.get(d["ext"], 0) + 1
    ext_str = ", ".join(f"{v} {k}" for k, v in sorted(ext_counts.items()))
    return f"  {xp3_name + ':':20s} {ok}/{total} OK ({ext_str})"


# --- Main orchestration ---


def identify_encryption(
    game_dir,
    use_frida=True,
    game_exe=None,
    frida_wait=15,
    dry_run=False,
    output_dir=None,
    verbose=0,
):
    """Run the full identification pipeline.

    Returns (exit_code, IdentificationReport).
    """
    report = IdentificationReport(game_dir=game_dir)

    # Discover
    print(f"Scanning: {game_dir}")
    xp3_files, enc_tpms, util_tpms = discover_game(game_dir)
    report.xp3_files = xp3_files
    report.enc_tpms = enc_tpms

    if not xp3_files:
        report.error = "No valid XP3 files found."
        print(f"  ERROR: {report.error}")
        return 2, report

    xp3_names = [os.path.basename(f) for f in xp3_files]
    tpm_names = [os.path.basename(f) for f in enc_tpms]
    print(f"  XP3 files: {', '.join(xp3_names)}")
    if tpm_names:
        print(f"  Encryption TPMs: {', '.join(tpm_names)}")
    else:
        print(f"  Encryption TPMs: none")

    # Check already known
    library = load_library()
    library_path = str(_XP3_PKG_DIR / "encryption_library.toml")

    print(f"\nChecking library...", end=" ")
    known = check_already_known(xp3_files, enc_tpms, library=library)
    if known:
        game_key, entry = known
        report.already_known = True
        title = entry.get("title", game_key)
        print(f"KNOWN: {game_key} ({title})")

        # Check for missing XP3 hashes and add them
        missing = find_missing_xp3_hashes(xp3_files, entry, library_path=library_path)
        if missing:
            print(f"  Missing XP3 hashes: {len(missing)}")
            for h, basename in missing:
                print(f"    {basename}: {h}")
            if dry_run:
                print("  (dry-run: would append to encryption_library.toml)")
            else:
                append_xp3_hashes(library_path, game_key, missing, game_dir)
                print(f"  Added {len(missing)} XP3 hashes to [games.{game_key}] in encryption_library.toml")
        else:
            print("  All XP3 hashes already in library.")

        return 0, report
    print("not found.")

    # Check unencrypted
    force_probe = False
    print("Checking encrypted flags...", end=" ")
    if check_unencrypted(xp3_files):
        print("no files have encrypted flag set.")

        # Verify by reading actual file contents
        print("Verifying files are genuinely unencrypted...", end=" ")
        confirmed, checked, failed = verify_unencrypted(xp3_files)

        if confirmed:
            report.is_unencrypted = True
            print(f"confirmed ({checked} files checked, magic bytes OK).")

            if not dry_run:
                unenc_path = str(_XP3_PKG_DIR / "unencrypted_library.toml")
                _append_unencrypted_entry(unenc_path, game_dir, xp3_files)
                print(f"Added to unencrypted_library.toml")
            else:
                print("(dry-run: would add to unencrypted_library.toml)")

            return 1, report
        elif failed > 0:
            print(f"FAILED ({failed}/{checked} files have wrong magic bytes).")
            print("  Files may be encrypted despite flag not being set; continuing detection...")
            force_probe = True
        else:
            print(f"inconclusive (only {checked} files with known magic found, need 3).")
            report.is_unencrypted = True

            if not dry_run:
                unenc_path = str(_XP3_PKG_DIR / "unencrypted_library.toml")
                _append_unencrypted_entry(unenc_path, game_dir, xp3_files)
                print(f"Added to unencrypted_library.toml")
            else:
                print("(dry-run: would add to unencrypted_library.toml)")

            return 1, report

    # Count encrypted files for display
    total_files = 0
    enc_count = 0
    for xp3_path in xp3_files:
        try:
            files = read_file_list(xp3_path)
            total_files += len(files)
            enc_count += sum(1 for f in files if f.encrypted)
        except Exception:
            pass
    print(f"{enc_count}/{total_files} files encrypted.")

    # Detect and verify candidates
    for candidate in detect_candidates(
        xp3_files,
        enc_tpms,
        library,
        use_frida=use_frida,
        game_exe=game_exe,
        frida_wait=frida_wait,
        force_probe=force_probe,
    ):
        method_label = {
            "tpm": "TPM hash lookup",
            "xp3_hash": "XP3 structure hash",
            "probe": "probe",
            "frida": "Frida analysis",
        }.get(candidate.method, candidate.method)

        param_str = ""
        if candidate.params:
            param_str = " " + " ".join(f"{k}={v}" for k, v in candidate.params.items())
        print(f"\nDetection: trying {method_label}... MATCH: {candidate.scheme_name}{param_str}")

        vr = verify_candidate(candidate, xp3_files)
        report.candidates_tried.append((candidate, vr))

        # Print verification details
        param_label = f" ({', '.join(f'{k}={v}' for k, v in candidate.params.items())})" if candidate.params else ""
        print(f"\nVerifying {candidate.scheme_name}{param_label}:")

        # Group details by XP3
        by_xp3 = {}
        for d in vr.details:
            by_xp3.setdefault(d["xp3"], []).append(d)
        for xp3_name, details in by_xp3.items():
            print(_format_verification_line(xp3_name, details))

        if vr.confirmed:
            print(f"Verification: CONFIRMED ({vr.successes}/{vr.total_checked} across {len(by_xp3)} archives)")
            report.confirmed_candidate = candidate

            entry_key, toml_text = generate_library_entry(game_dir, candidate, xp3_files, enc_tpms)

            if dry_run:
                print(f"\n(dry-run) Would add to encryption_library.toml:")
                print(toml_text)
            else:
                append_to_library(library_path, entry_key, toml_text)
                report.library_entry_added = True
                print(f"\nAdded [{entry_key}] to encryption_library.toml")
                print(f"  encryption = \"{candidate.scheme_name}\"{param_label}")
                tpm_count = len(enc_tpms)
                xp3_count = sum(1 for f in xp3_files if not os.path.basename(f).startswith("patch"))
                print(f"  TPM hashes: {tpm_count}, XP3 hashes: {xp3_count}")

            return 0, report
        else:
            print(f"Verification: FAILED ({vr.successes}/{vr.total_checked} OK, {vr.failures} failures)")

    # No candidate confirmed
    print("\nNo candidate confirmed.")
    if output_dir is None:
        output_dir = os.path.join(os.getcwd(), os.path.basename(game_dir) + "_failure_report")
    generate_failure_report(game_dir, report, output_dir)
    print(f"Failure report written to: {output_dir}")
    return 2, report


def _append_unencrypted_entry(library_path, game_dir, xp3_files):
    """Append to the unencrypted library."""
    dir_name = os.path.basename(os.path.normpath(game_dir))
    parent_name = os.path.basename(os.path.dirname(os.path.normpath(game_dir)))
    slug = _slugify(parent_name + "-" + dir_name) if parent_name else _slugify(dir_name)

    lines = [
        f"\n[games.{slug}]",
        f'title = "{dir_name}"',
        f'publisher = "{parent_name}"' if parent_name else 'publisher = "Unknown"',
        "xp3_hashes = [",
    ]
    for xp3_path in sorted(xp3_files):
        basename = os.path.basename(xp3_path)
        if basename.startswith("patch"):
            continue
        try:
            h = hash_xp3_structure(xp3_path)
            lines.append(f'    "{h}", # {basename}')
        except Exception:
            pass
    lines.append("]")

    with open(library_path, "a") as f:
        f.write("\n".join(lines))
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Automatically identify and verify XP3 encryption for a game.")
    parser.add_argument("game_dir", help="Path to the game directory")
    parser.add_argument("--no-frida", action="store_true", help="Skip Frida analysis (no Wine needed)")
    parser.add_argument("--game-exe", default=None, help="Game executable for Frida (auto-detected if omitted)")
    parser.add_argument("--frida-wait", type=int, default=15, help="Seconds to wait for Wine startup (default: 15)")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be added, don't modify library")
    parser.add_argument("--output", default=None, help="Directory for failure reports")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v info, -vv debug)")
    args = parser.parse_args()

    if args.verbose >= 2:
        logging.basicConfig(level=logging.DEBUG, format='%(name)s: %(levelname)s: %(message)s')
    elif args.verbose >= 1:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    else:
        logging.basicConfig(level=logging.WARNING)

    # Suppress noisy xp3file library messages (expected during probing without encryption)
    if args.verbose < 2:
        logging.getLogger('xp3file').setLevel(logging.CRITICAL)

    if not os.path.isdir(args.game_dir):
        print(f"Error: {args.game_dir} is not a directory", file=sys.stderr)
        sys.exit(2)

    # Auto-detect game exe if not provided
    game_exe = args.game_exe
    if game_exe is None and not args.no_frida:
        for f in os.listdir(args.game_dir):
            if f.lower().endswith(".exe"):
                game_exe = os.path.join(args.game_dir, f)
                break

    exit_code, report = identify_encryption(
        game_dir=os.path.abspath(args.game_dir),
        use_frida=not args.no_frida,
        game_exe=game_exe,
        frida_wait=args.frida_wait,
        dry_run=args.dry_run,
        output_dir=args.output,
        verbose=args.verbose,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
