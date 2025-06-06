import os
import sys
import argparse
import platform
import subprocess

from setuptools import setup, Extension
from Cython.Build import cythonize

CWD = os.path.realpath(os.path.dirname(__file__))
CPP_STD = "c++17"


def build_casclib(debug: bool):
    print("Building CascLib...")

    build_dir = os.path.join(CWD, "casclib", "build")

    os.makedirs(build_dir, exist_ok=True)
    os.chdir(build_dir)

    build_config = "Release" if not debug else "Debug"

    cmake_defines = [
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
        f"-DCMAKE_BUILD_TYPE={build_config}",
        "-DCASC_BUILD_SHARED_LIB=OFF",
        "-DCASC_BUILD_STATIC_LIB=ON",
    ]

    if sys.platform != "win32":
        cmake_defines.extend(["-DCMAKE_CXX_FLAGS=-fPIC", "-DCMAKE_C_FLAGS=-fPIC"])

    status = subprocess.call(["cmake", "..", *cmake_defines])

    if status:
        print("Error configuring CascLib. See CMake error above.")
        sys.exit(1)

    status = subprocess.check_call(
        ["cmake", "--build", ".", f"--config {build_config}"]
    )

    if status:
        print("Error building CascLib. See error above.")
        sys.exit(1)

    status = subprocess.call(
        ["cmake", "--install", ".", f"--prefix {CWD}", f"--config {build_config}"]
    )

    if status:
        print("Error building CascLib. Error setting install configuration")
        sys.exit(1)

    print("Successfully built CascLib.")


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
        extra_compile_args = [f"-std={CPP_STD}", "-O3"]
        extra_link_args = []

    elif platform.system() == "Windows":
        extra_compile_args = [f"/std:{CPP_STD}"]
        extra_link_args = []
        if debug:
            extra_compile_args = extra_compile_args.append("/Zi")
            extra_link_args = extra_link_args.extend(["/DEBUG:FULL"])

    else:
        extra_compile_args = [f"-std={CPP_STD}", "-O3"]
        extra_link_args = []

    setup(
        name="pycasclib",
        ext_modules=cythonize(
            Extension(
                "pycasclib.core",
                sources=["src/pycasclib/*.pyx"],
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
