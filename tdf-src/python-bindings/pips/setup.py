import os
import sys
import io

from setuptools import setup, Extension

package_name = 'opentdf'

def get_version():
    python_sdk_version = None

    try:
        with io.open(os.path.join(os.path.abspath(os.path.dirname(__file__)), '..', '..', '..', 'VERSION')) as f:
            python_sdk_version = f.read().strip()
    except FileNotFoundError as error:
        print(f'VERSION file not found make sure to run from the same directory as this file. Exception:{error}')
        raise

    git_branch = None
    if 'BUILDKITE_BRANCH' in os.environ:
        git_branch = os.environ['BUILDKITE_BRANCH']

    build_number = None
    if 'BUILDKITE_BUILD_NUMBER' in os.environ:
        build_number = os.environ['BUILDKITE_BUILD_NUMBER']

    if git_branch and build_number:
        if git_branch == 'develop':
            python_sdk_version = f'{python_sdk_version}a{build_number}'
        elif git_branch == 'master':
            python_sdk_version = f'{python_sdk_version}b{build_number}'

    print(f'Platform:{sys.platform}')
    print(f'Python SDK version:{python_sdk_version}')
    return python_sdk_version

version = get_version()

# Read the readme text from VERSION file.
def load_readme():
     with io.open('../README.md', encoding="utf-8") as f:
        return f.read()

include_dirs = []
library_dirs = []
library_dirs = library_dirs.append(os.path.join('..', '..', '..', "tdf-lib-cpp", "lib"))

tdf_library = 'libopentdf_static_combined.a'
if sys.platform == 'win32':
    tdf_library = 'opentdf_static_combined.lib'

libdir = os.path.join('..', '..', "lib")
library_file = os.path.join('..', '..', '..', "tdf-lib-cpp", "lib", tdf_library)

extra_objects = []
extra_objects.append(library_file)
if sys.platform == 'win32':
    extra_objects.append("crypt32.lib")
    extra_objects.append("ws2_32.lib")
    extra_objects.append("bcrypt.lib")
    extra_objects.append("user32.lib")
    extra_objects.append("advapi32.lib")
    extra_objects.append("gdi32.lib")

cflags = ["-std=c++17", "-fvisibility=hidden"]

cflags = []
if sys.platform == 'darwin':
    cflags.append('-std=c++17')
    cflags.append('-fvisibility=hidden')
    cflags.append('-mmacosx-version-min=10.14')
else:
    cflags.append('-std=c++17')
    cflags.append('-fvisibility=hidden')

class get_pybind_include(object):
    """Helper class to determine the pybind11 include path
    The purpose of this class is to postpone importing pybind11
    until it is actually installed, so that the ``get_include()``
    method can be invoked. """

    def __init__(self, user=False):
        self.user = user

    def __str__(self):
        import pybind11
        return pybind11.get_include(self.user)

tf3_module = Extension(
    package_name,
    sources=["python_module.cpp"],
    extra_compile_args=cflags,
    include_dirs=[os.path.join(libdir, "include"),
                  os.path.join(libdir, "src"),
                  get_pybind_include(),
                  get_pybind_include(user=True)],
    library_dirs=library_dirs,
    extra_objects=extra_objects,
    libraries=extra_objects,
    language='c++')

if sys.platform == 'win32':
    tf3_module = Extension(
        package_name,
        sources=["python_module.cpp"],
        include_dirs=[os.path.join(libdir, "include"),
                    os.path.join(libdir, "src"),
                    get_pybind_include(),
                    get_pybind_include(user=True)],
        extra_objects=extra_objects,
        extra_compile_args=['/std:c++17', '/MD', '/O2', '/Ob2'],
        extra_link_args=extra_objects,
        language='c++')

setup(
    name=package_name,
    version=version,
    author='Virtru',
    author_email='developers@virtru.com',
    url='https://developer.virtru.com/',
    license='MIT',
    description='Python Wrapper for OpenTDF SDK',
    long_description=load_readme(),
    long_description_content_type='text/markdown',
    install_requires=[],
          classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Operating System :: Unix',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development',
        'Topic :: Software Development :: Libraries :: Application Frameworks'
        ],
    ext_modules=[tf3_module],
)
