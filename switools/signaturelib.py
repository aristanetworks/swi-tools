# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from __future__ import absolute_import, division, print_function
import os
import subprocess
import zipfile

SWI_SIG_FILE_NAME = 'swi-signature'
SWIX_SIG_FILE_NAME = 'swix-signature'

def getSigFileName( swiFile ):
   if swiFile.lower().endswith( ".swix" ):
      return SWIX_SIG_FILE_NAME
   return SWI_SIG_FILE_NAME

def runCmd( cmd, workDir=None ):
   try:
      subprocess.check_call( cmd, cwd=workDir )
   except subprocess.CalledProcessError:
      return False
   return True

def getOptimizations( swi, workDir ):
   with zipfile.ZipFile( swi ) as zf:
      if 'swimSqshMap' not in zf.namelist():
         return None
      optims = []
      for line in zf.read( 'swimSqshMap' ).decode( 'utf-8' ).split():
         optim, _ = line.split( "=", 1 )
         optims.append( optim )
      return optims

def extractSwadapt( swi, workDir ):
   # zipfile.py does not honor file settings like +x, so use proven /usr/bin/zip
   cmd = [ "unzip", "-o", "-qq", os.path.abspath( swi ), "swadapt" ]
   return runCmd( cmd, workDir )

def checkIsSwiFile( swi, workDir ):
   if not os.path.isfile( swi ):
      return False
   # unzip spits warnings when extracting non-existant files, so check first :-(
   cmd = [ "unzip", "-Z1", swi ]
   if not "version" in subprocess.check_output( cmd ).decode( 'utf-8' ).split():
      return None # legacy image
   cmd = [ "unzip", "-o", "-qq", os.path.abspath( swi ), "version" ]
   return runCmd( cmd, workDir )

def adaptSwi( swi, optimImage, optim, workDir ):
   cmd = [ "%s/swadapt" % workDir, os.path.abspath( swi ), optimImage, optim ]
   return runCmd( cmd, workDir )
