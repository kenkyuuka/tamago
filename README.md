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
