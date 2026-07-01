"""Wheel build for the qsafe Python bindings.

The package is pure ctypes; the native piece is libqsafe, built with the
project Makefile (`make lib`, which needs OpenSSL 3 and liboqs on the build
host) and bundled into the package directory. The wheel is therefore tagged
py3-none-<platform>: any Python 3, one wheel per OS/arch.
"""

import os
import shutil
import subprocess

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.dist import Distribution

try:
    from wheel.bdist_wheel import bdist_wheel
except ImportError:  # building an sdist doesn't need wheel
    bdist_wheel = None

ROOT = os.path.dirname(os.path.abspath(__file__))
LIB_NAMES = ("libqsafe.so", "libqsafe.dylib", "libqsafe.dll")


class BuildPyWithLib(build_py):
    """Runs `make lib` and drops the shared library inside the package."""

    def run(self):
        subprocess.check_call(["make", "lib"], cwd=ROOT)
        super().run()
        dest = os.path.join(self.build_lib, "qsafe")
        os.makedirs(dest, exist_ok=True)
        found = False
        for name in LIB_NAMES:
            src = os.path.join(ROOT, name)
            if os.path.exists(src):
                shutil.copy2(src, dest)
                found = True
        if not found:
            raise RuntimeError("make lib succeeded but no libqsafe.{so,dylib,dll} found")


class BinaryDistribution(Distribution):
    def has_ext_modules(self):
        return True  # platform wheel, not purelib


cmdclass = {"build_py": BuildPyWithLib}

if bdist_wheel is not None:
    class BDistWheel(bdist_wheel):
        def get_tag(self):
            # ctypes only: independent of the Python version and ABI.
            _, _, plat = super().get_tag()
            return "py3", "none", plat

    cmdclass["bdist_wheel"] = BDistWheel

setup(
    distclass=BinaryDistribution,
    cmdclass=cmdclass,
    package_data={"qsafe": ["libqsafe.*"]},
)
