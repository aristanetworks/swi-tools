# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from __future__ import absolute_import, division, print_function
import os

SWI_SIG_FILE_NAME = 'swi-signature'
SWIX_SIG_FILE_NAME = 'swix-signature'

def getSigFileName( swiFile ):
   if swiFile.lower().endswith( ".swix" ):
      return SWIX_SIG_FILE_NAME
   return SWI_SIG_FILE_NAME

def getOptimizations( swi, workDir ):
   ret = os.system( "set -e; swi=$(readlink -f %s); cd %s; "
                    "unzip -q -o $swi swimSqshMap" % ( swi, workDir ) )
   if ret:
      return None # legacy image
   optims = []
   with open( "%s/swimSqshMap" % workDir ) as f:
      for line in f:
         optim, _ = line.split( "=", 1 )
         optims.append( optim )
   os.system( "rm %s/swimSqshMap" % workDir )
   return optims

def extractSwadapt( swi, workDir ):
   ret = os.system( "set -e; image=$(readlink -f %s); cd %s;"
                    "unzip -o -q $image swadapt" % ( swi, workDir ) )
   if ret:
      print( "Error: '%s' does not contain the 'swadapt' utility" % swi )
      shutil.rmtree( workDir )
      sys.exit( -1 )
