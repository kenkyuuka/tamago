"""Custom hatch build hook to compile the optional C accelerator extensions."""

from __future__ import annotations

import os
import subprocess
import sysconfig

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

# (package directory under src/tamago/formats, module name).  Each has a
# pure-Python fallback that is used when compilation fails.
ACCELERATORS = [
    ('xp3', '_tlg_accel'),
    ('yuris', '_murmur_accel'),
]


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = 'custom'

    def initialize(self, version, build_data):
        ext_suffix = sysconfig.get_config_var('EXT_SUFFIX') or '.so'
        include = sysconfig.get_path('include')

        for package, module in ACCELERATORS:
            src = os.path.join(self.root, 'src', 'tamago', 'formats', package, f'{module}.c')
            if not os.path.exists(src):
                continue

            out_name = f'{module}{ext_suffix}'
            out_path = os.path.join(self.root, 'src', 'tamago', 'formats', package, out_name)
            try:
                subprocess.check_call(
                    ['gcc', '-O2', '-shared', '-fPIC', f'-I{include}', '-o', out_path, src],
                    stderr=subprocess.PIPE,
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                # C compilation failed; pure-Python fallback will be used at runtime.
                continue

            # Include the compiled .so in the wheel.
            rel_path = os.path.join('tamago', 'formats', package, out_name)
            build_data['force_include'][out_path] = rel_path
