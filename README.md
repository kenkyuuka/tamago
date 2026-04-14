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

## Installation

```console
pip install tamago
```

To enable TLG image conversion, install with the `images` extra:

```console
pip install tamago[images]
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
