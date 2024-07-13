import os
import sys
import argparse
import platform
import subprocess

from setuptools import setup, Extension
from Cython.Build import cythonize

CWD = os.path.realpath(os.path.dirname(__file__))


def build_casclib(debug: bool):
    print("Building CascLib...")

    build_dir = os.path.join(CWD, "casclib", "build")

    os.makedirs(build_dir, exist_ok=True)
    os.chdir(build_dir)

    build_config = "Release" if not debug else "Debug"

    cmake_defines = [
        f"-DCMAKE_BUILD_TYPE={build_config}",
        "-DCASC_BUILD_SHARED_LIB=ON",
        "-DCASC_BUILD_STATIC_LIB=ON",
    ]

    if sys.platform != "win32":
        cmake_defines.extend(["-DCMAKE_CXX_FLAGS=-fPIC", "-DCMAKE_C_FLAGS=-fPIC"])

    status = subprocess.call(["cmake", "..", *cmake_defines])

    if status:
        print("Error building CASCLib. See CMake error above.")
        sys.exit(1)

    status = subprocess.check_call(
        ["cmake", "--build", ".", f"--config {build_config}"]
    )

    if status:
        print("Error building CASCLib. See error above.")
        sys.exit(1)

    status = subprocess.call(
        ["cmake", "--install", ".", f"--prefix {CWD}", f"--config {build_config}"]
    )

    if status:
        print("Error building CASCLib. Error setting install configuration")
        sys.exit(1)


def build(debug: bool):
    build_casclib(debug)

    os.chdir(CWD)

    static_libraries = ["casc"]
    static_lib_dir = "lib"
    libraries = []
    library_dirs = []
    extra_objects = []
    define_macros = [("CYTHON_LIMITED_API", "1")]

    if sys.platform == "win32":
        libraries.extend(static_libraries)
        library_dirs.append(static_lib_dir)
        extra_objects = []
        define_macros.append(("CASCLIB_NO_AUTO_LINK_LIBRARY", None))
    else:  # POSIX
        extra_objects = [
            "{}/lib{}.a".format(static_lib_dir, l) for l in static_libraries
        ]
        libraries.append("z")

    # compiler and linker settings
    if platform.system() == "Darwin":
        extra_compile_args = ["-std=c++17", "-O3"]
        extra_link_args = []

    elif platform.system() == "Windows":
        extra_compile_args = ["/std:c++17"]
        extra_link_args = []
        if debug:
            extra_compile_args = extra_compile_args.append("/Zi")
            extra_link_args = extra_link_args.extend(["/DEBUG:FULL"])

    else:
        extra_compile_args = ["-std=c++17", "-O3"]
        extra_link_args = []

    setup(
        name="pycasc",
        ext_modules=cythonize(
            Extension(
                "pycasc.core",
                sources=["src/pycasc/*.pyx"],
                language="c++",
                libraries=libraries,
                library_dirs=library_dirs,
                include_dirs=["include"],
                extra_objects=extra_objects,
                define_macros=define_macros,
                extra_compile_args=extra_compile_args,
                extra_link_args=extra_link_args,
                py_limited_api=True,
            ),
            compiler_directives={"language_level": 3, "profile": True},
        ),
        requires=["Cython"],
    )

    print("Succesfully built CASC extension.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pycasc_debug",
        action="store_true",
        help="Compile extension and CascLib in debug mode.",
    )
    args, unk = parser.parse_known_args()

    debug = False
    if args.pycasc_debug:
        debug = True
        sys.argv.remove("--pycasc_debug")

    build(debug)
