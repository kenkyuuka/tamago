"""Custom hatch build hook to compile the TLG C accelerator extension."""

from __future__ import annotations

import os
import subprocess
import sysconfig

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    PLUGIN_NAME = 'custom'

    def initialize(self, version, build_data):
        src = os.path.join(self.root, 'src', 'tamago', 'formats', 'xp3', '_tlg_accel.c')
        if not os.path.exists(src):
            return

        ext_suffix = sysconfig.get_config_var('EXT_SUFFIX') or '.so'
        out_name = f'_tlg_accel{ext_suffix}'
        out_path = os.path.join(self.root, 'src', 'tamago', 'formats', 'xp3', out_name)
        include = sysconfig.get_path('include')

        try:
            subprocess.check_call(
                ['gcc', '-O2', '-shared', '-fPIC', f'-I{include}', '-o', out_path, src],
                stderr=subprocess.PIPE,
            )
        except (subprocess.CalledProcessError, FileNotFoundError):
            # C compilation failed; pure-Python fallback will be used at runtime.
            return

        # Include the compiled .so in the wheel.
        rel_path = os.path.join('tamago', 'formats', 'xp3', out_name)
        build_data['force_include'][out_path] = rel_path
