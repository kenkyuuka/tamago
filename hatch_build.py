"""Custom hatch build hook to compile the optional C accelerator extensions.

Each accelerator has a pure-Python fallback, so the package works without
them, only far slower.  A wheel that contains them is tagged for the platform
it was built on; one that doesn't stays ``py3-none-any``.

On CPython 3.11+ (except free-threaded builds) the extensions are compiled
against the stable ABI, so a single ``cp311-abi3`` wheel serves every later
version too.  3.11 is the first version whose limited API includes the buffer
protocol the accelerators use.

Environment variables:

``TAMAGO_NO_ACCEL=1``
    Don't compile anything; build a pure-Python wheel.
``TAMAGO_REQUIRE_ACCEL=1``
    Fail the build if an accelerator can't be compiled, instead of warning and
    falling back to pure Python.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import sysconfig

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# (package directory under src/tamago/formats, module name).
ACCELERATORS = [
    ('xp3', '_tlg_accel'),
    ('yuris', '_murmur_accel'),
]

LIMITED_API = (3, 11)
LIMITED_API_HEX = '0x030B0000'


def _flag(name: str) -> bool:
    return os.environ.get(name, '') not in ('', '0')


def use_limited_api() -> bool:
    """Return True if this interpreter can build stable-ABI extensions."""
    return (
        sys.implementation.name == 'cpython'
        and sys.version_info >= LIMITED_API
        and not sysconfig.get_config_var('Py_GIL_DISABLED')
    )


def abi3_tag() -> str:
    """Return the wheel tag for stable-ABI extensions built on this platform."""
    platform = re.sub(r'[-.]', '_', sysconfig.get_platform())
    return f'cp{LIMITED_API[0]}{LIMITED_API[1]}-abi3-{platform}'


def _shadows_abi3(filename: str, module: str) -> bool:
    """Return True if *filename* is a version-specific build of *module* that
    an interpreter able to load the abi3 build would import in preference."""
    match = re.match(rf'{re.escape(module)}\.cpython-3(\d+)(t?)-', filename)
    return bool(match) and int(match.group(1)) >= LIMITED_API[1] and not match.group(2)


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = 'custom'

    def initialize(self, version, build_data):
        if self.target_name != 'wheel' or _flag('TAMAGO_NO_ACCEL'):
            return

        limited = use_limited_api()
        built = []
        for package, module in ACCELERATORS:
            try:
                path = self._compile(package, module, limited)
            except Exception as e:
                if _flag('TAMAGO_REQUIRE_ACCEL'):
                    raise RuntimeError(f'failed to compile {module} (TAMAGO_REQUIRE_ACCEL is set): {e}') from e
                self.app.display_warning(f'Could not compile {module}; it will fall back to pure Python: {e}')
                continue

            pkg_dir = os.path.join(self.root, 'src', 'tamago', 'formats', package)
            if version == 'editable':
                # Editable installs import straight from src/, so the
                # extension has to live there.  Remove older version-specific
                # builds that would otherwise be imported instead of this one.
                if limited:
                    for name in os.listdir(pkg_dir):
                        if _shadows_abi3(name, module):
                            os.remove(os.path.join(pkg_dir, name))
                shutil.copy2(path, pkg_dir)
            else:
                rel = os.path.join('tamago', 'formats', package, os.path.basename(path))
                build_data['force_include'][path] = rel
            built.append(module)

        if built:
            build_data['pure_python'] = False
            if limited:
                build_data['tag'] = abi3_tag()
            else:
                build_data['infer_tag'] = True

    def _compile(self, package: str, module: str, limited: bool) -> str:
        """Compile one accelerator and return the path of the built extension.

        setuptools' build_ext picks the right compiler and flags for the
        platform (gcc/clang on Unix, MSVC on Windows) and names the output
        with the matching suffix (``.abi3.so``, ``.cpython-310-….so``,
        ``.pyd``).
        """
        from setuptools import Distribution, Extension
        from setuptools.command.build_ext import build_ext

        source = os.path.join('src', 'tamago', 'formats', package, f'{module}.c')
        ext = Extension(
            f'tamago.formats.{package}.{module}',
            [source],
            py_limited_api=limited,
            define_macros=[('Py_LIMITED_API', LIMITED_API_HEX)] if limited else [],
        )
        build_dir = os.path.join(self.root, 'build', 'accel')
        cmd = build_ext(Distribution({'name': 'tamago-accel', 'ext_modules': [ext]}))
        cmd.build_lib = os.path.join(build_dir, 'lib')
        cmd.build_temp = os.path.join(build_dir, 'temp')
        cmd.force = True
        cwd = os.getcwd()
        os.chdir(self.root)  # build_ext resolves sources relative to the cwd
        try:
            cmd.ensure_finalized()
            cmd.run()
        finally:
            os.chdir(cwd)
        return os.path.join(self.root, cmd.get_ext_fullpath(ext.name))
