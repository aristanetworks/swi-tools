# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup( name='switools',
       version='1.2',
       description='Tools for handling Arista SWI/X',
       long_description=long_description,
       long_description_content_type='text/markdown',
       packages=['switools', 'swixtools'],
       install_requires=[ 'jsonschema', 'pyparsing', 'PyYAML', 'M2Crypto' ],
       test_suite="tests",
       entry_points = {
           'console_scripts': [ 'verify-swi=switools.verifyswi:main',
                                'swi-signature=switools.swisignature:main',
                                'swix-create=swixtools.create:main',
                                'swix-signature=switools.swisignature:main',
                                'verify-swix=switools.verifyswi:main',
                                'swi-signing-service=switools.swisigningservice:main'
                              ],
       },
       url='https://github.com/aristanetworks/swi-tools',
       zip_safe=False,
       include_package_data=True )
