# Copyright 2019 Virtru Corporation
#
# SPDX - License - Identifier: MIT
#
from distutils.core import setup

import sys
if sys.version_info < (3,0):
    sys.exit('Sorry, Python < 3.0 is not supported')

setup(
    name         = '${PROJECT_NAME}',
    version      = '${PACKAGE_VERSION}',
    description  = 'Python tdf library',
    author       = 'virtru.com',
    author_email = 'developers@virtru.com',
    url          = 'https://developer.virtru.com/',
    packages     = ['${PROJECT_NAME}'],
    package_data = {
        '': ['${TDF_PYTHON_BINDINGS_FILENAME}']
    }
)