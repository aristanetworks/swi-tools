# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from setuptools import setup

setup( name='switools',
       version='1.0',
       description='Tools for handling Arista SWI/X',
       packages=['switools', 'swixtools'],
       install_requires=[ 'M2Crypto' ],
       test_suite="tests",
       entry_points = {
           'console_scripts': [ 'verify-swi=switools.verifyswi:main',
                                'swi-signature=switools.swisignature:main',
                                'swix-create=swixtools.create:main',
                                'swix-signature=switools.swisignature:main',
                              ],
       },
       url='https://github.com/aristanetworks/swi-tools',
       zip_safe=False,
       include_package_data=True )
