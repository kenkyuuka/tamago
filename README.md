# tamago

Multi-format game archive toolkit.

Requires Python 3.10 or later.

## Supported formats

| Format | Engine | Extract | Create |
|--------|--------|:-------:|:------:|
| XP3    | [KiriKiri](https://github.com/kenkyuuka/research-vault/blob/main/engines/KiriKiri.md) | yes | yes |
| DET    | [μ-GameOperationSystem](https://github.com/kenkyuuka/research-vault/blob/main/engines/%CE%BC-GameOperationSystem.md) | yes | yes |
| GSP    | [AGSD](https://github.com/kenkyuuka/research-vault/blob/main/engines/AGSD.md) | yes | yes |
| ARC    | AdvHD (WillPlus V2) | yes | yes |
| VF     | LiveMaker | yes | yes |
| RPA    | Ren'Py | yes | yes |
| DXA    | DxLib (versions 1–4) | yes | yes |
| MED    | Fudegaki Soft (DxLib) | yes | yes |
| PCK    | ANIM (`*_wave.pck`, `psbpack.dat`) | yes | yes |
| YPF    | YU-RIS (versions 461–500; also YSTB scripts and YCG images) | yes | yes |
| DAT    | BlackRainbow ADVDX (`.dat`/`.pak`; also `_BMD` images) | yes | yes |
| PSB    | E-mote models (versions 2–4; e.g. from ANIM's `psbpack.dat`) | yes | yes |
| ARC    | AI6WIN (elf, Silky's) | yes | yes |
| GPK/VPK | Black Cyc (also Cyc No-nos, CYCLET) | yes | yes |
| HE0–HE4 | SCUMM, Humongous Entertainment (Freddi Fish 1–5) | yes | no |

## Installation

```console
pip install tamagoarc
```

## Usage

### tamago CLI

tamago auto-detects archive formats by magic bytes and, for XP3 archives, automatically identifies the correct encryption scheme.

```console
# Identify an archive's format
tamago identify data.xp3

# Extract an archive (auto-detects format and encryption)
tamago extract data.xp3 output_dir

# Use format subcommands for format-specific options
tamago xp3 extract data.xp3 output_dir --encryption hash-xor --key 3
tamago det create source_dir output.det --index-format atm

# Create an archive (format must be specified)
tamago create --format xp3 source_dir output.xp3
```

ANIM games also encipher their scripts and images as single files (`*_sce.dat`, `*_define.dat`, `cg/*.gax`). Decrypt or encrypt a file, or every such file under a directory:

```console
tamago anim decrypt game_dir/cg/BG010.gax BG010.png
tamago anim decrypt game_dir decrypted_dir
tamago anim encrypt decrypted_dir enciphered_dir
```

YU-RIS archives must be recreated with the version, name key and name-length table the game expects. `--like` copies them from one of the game's own archives:

```bash
tamago yuris extract pac/cg.ypf cg_dir --convert-ycg   # YCG images (stored as .png) become real PNGs
tamago yuris create cg_dir cg.ypf --like pac/cg.ypf --encode-ycg
tamago yuris decrypt ysbin_dir plain_dir               # YSTB scripts; the key is recovered automatically
tamago yuris encrypt plain_dir ysbin_dir --key 96ac6fd3
tamago yuris decode-ycg ycg_dir png_dir                # standalone YCG <-> PNG conversion
tamago yuris encode-ycg png_dir ycg_dir
```

BlackRainbow ADVDX archives address their members by slot number, and many members have no name. Extraction writes `_advdx_manifest.json` next to the files, recording each member's slot and stored name and the archive's header. `create` reads it back, so an extracted archive is rebuilt with every member in its slot. Script and read-flag archives carry a game ID that the game checks; the manifest keeps it, or give it with `--game-id`:

```bash
tamago blackrainbow extract image/sj_bga.dat bga_dir --convert-bmd   # _BMD images become PNG
tamago blackrainbow create bga_dir sj_bga.dat                         # PNGs are encoded back to _BMD
tamago blackrainbow create spt_dir sj_spt.dat --kind script --game-id 15432 --slots 192
tamago blackrainbow decode-bmd bmd_dir png_dir                        # standalone _BMD <-> PNG conversion
tamago blackrainbow encode-bmd png_dir bmd_dir
```

AI6WIN archives (`mes.arc`, `Data.arc`, `Voice.arc`, ...) are extracted with a manifest, `_ai6win_manifest.json`, recording the order of the members and which ones are compressed, so `create` rebuilds the original archive byte for byte. New files are added after the listed ones, compressed if they are scripts or data (`.mes`, `.lib`, `.area`, `.ax`, `.bin`, `.mov`) as in the games' own archives; `--compress` or `--no-compress` overrides this for every member:

```bash
tamago extract mes.arc mes_dir
tamago create --format ai6win mes_dir mes.arc
```

Black Cyc packs come in pairs: an index and a data file with the same name, `.gtb` + `.gpk` for `.dwq` images and `.vtb` + `.vpk` for `.vaw` voices. Give either file to `extract`. `create` writes both, and rebuilding an extracted pack reproduces the original files byte for byte:

```bash
tamago extract dwq/bg0.gpk bg0_dir
tamago create --format blackcyc bg0_dir dwq/bg0.gpk     # writes bg0.gpk and bg0.gtb
```

Humongous Entertainment's SCUMM games (Freddi Fish and its siblings) are extracted one file at a time: the index (`.he0`), the room data (`.he1`, or `.(A)` in later games), speech (`.he2`) and music (`.he4`). Sounds, speech and music become WAV files, and room backgrounds, object images and sprites become PNG. Costumes (characters and other animations) are written as stored, with each of their pictures ("cels") as a PNG in a folder beside them; tamago does not assemble cels into animations. Where a costume names its animation sequences (Freddi Fish 2 and 3), the folder takes the first name (`costume-0003-freddi_swims_in/`). Scripts and other blocks are written as stored. A room data file uses the `.he0` beside it to name resources by number (`room-012/sound-0345.wav`); speech lines are named by their offset in `.he2`, which is how scripts refer to them. `--no-convert` writes every block as stored instead. SCUMM files cannot be created:

```bash
tamago extract Freddi.he1 freddi_rooms      # room-NNN/background.png, objects/*.png, sound-*.wav, costume-*/cel-*.png, ...
tamago extract Freddi.he2 freddi_speech     # talk-<offset>.wav
tamago scumm extract --no-convert Freddi.he4 freddi_music
```

E-mote PSB files are decompiled to `psb.json` (the value tree), the resource chunks (`resources/0.bin`, ...) and the texture atlases as PNG, and compiled back from the JSON and chunks. The encryption key is recovered from version 3 and 4 files; ANIM's is built in, and others can be given with `--key`. The tree in `psb.json` writes single-precision floats as plain numbers, and resource references and other values JSON lacks as one-key objects (`{"$resource": 0}`):

```console
tamago psb extract Malice100.psb model_dir     # psb.json, resources/, textures/*.png
tamago psb create model_dir Malice100.psb      # encrypted as the original was (--no-encrypt for a plain file)
tamago psb decrypt Malice100.psb plain.psb
tamago psb info Malice100.psb
```

### Python API

```python
from tamago.formats.xp3 import XP3File

# Extract an archive
with XP3File("data.xp3") as xp3:
    xp3.extract_all("output_dir")

# Extract with explicit encryption
from tamago.formats.xp3.encryption import HashXorEncryption

enc = HashXorEncryption(shift=3)
with XP3File("data.xp3", encryption=enc) as xp3:
    xp3.extract_all("output_dir")

# Auto-detect encryption
from tamago.formats.xp3.detect import auto_detect

enc = auto_detect("data.xp3")
with XP3File("data.xp3", encryption=enc) as xp3:
    xp3.extract_all("output_dir")

# Create an archive
from pathlib import Path

with XP3File("output.xp3", "x") as xp3:
    xp3.write_all(Path("source_dir"))
```

## XP3 Encryption

XP3 archives used by KiriKiri games are often encrypted with a game-specific scheme implemented in a `.tpm` plugin. tamago supports the encryption used by several games (including automatic detection of the encryption).

If the game you are interested in is not supported, please raise an issue, including a VNDB link to the game.

## Development

This project uses [Hatch](https://hatch.pypa.io/) as the build system.

### Setup

```console
pip install hatch
```

### Running tests

```console
hatch run test                    # run all tests
hatch run test -k test_name       # run a single test by name
hatch run cov                     # tests + coverage report
```

### Linting and formatting

```console
hatch run lint:style     # check style (ruff + black)
hatch run lint:typing    # type checking (mypy)
hatch run lint:fmt       # auto-format (black + ruff --fix)
hatch run lint:all       # style + typing
```

## License

tamago is distributed under the terms of the [MIT license](LICENSE).
