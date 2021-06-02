#!/usr/bin/env python3
# Copyright ( c ) 2021 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

'''
This module is responsible for packaging a SWIX file.
'''

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

def dealWithExistingOutputFile( outputSwix, force ):
   '''
   If the desired output file exists, fail unless `force` is specified.
   '''
   if os.path.exists( outputSwix ):
      if force:
         os.remove( outputSwix )
      else:
         sys.exit( f'File {outputSwix!r} exists: use --force to overwrite.\n' )

def sha1sum( filename, blockSize=65536 ):
   '''
   Compute the SHA1 sum of a file.
   We read in blocks in case of large files.
   '''
   result = hashlib.sha1()
   with open( filename, 'rb' ) as f:
      block = f.read( blockSize )
      while block:
         result.update( block )
         block = f.read( blockSize )

   return result.hexdigest()

def createManifest( tempDir, rpms ):
   '''
   Create a manifest file for the SWIX which contains:
   - The format version.
   - The name of the primary RPM.
   - The SHA1 digest of all RPMs.
   '''
   manifestBaseName = 'manifest.txt'
   manifestFileName = os.path.join( tempDir, manifestBaseName )
   basename = os.path.basename
   try:
      with open( manifestFileName, 'w' ) as manifest:
         print( 'format: 1', file=manifest )
         print( f'primaryRpm: {basename( rpms[0] )}', file=manifest )
         for rpm in rpms:
            print( f'{basename( rpm )}-sha1: {sha1sum( rpm )}', file=manifest )
   except Exception as e:
      sys.exit( f'{manifestFileName}: {e}\n' )

   return manifestFileName

def create( outputSwix=None, info=None, rpms=None, force=False ):
   '''
   Create a SWIX file named `outputSwix` given a list of RPMs.
   `info` is currently unused.
   '''
   dealWithExistingOutputFile( outputSwix, force )
   try:
      tempDir = tempfile.mkdtemp( suffix='.tempDir',
                                  dir='.',
                                  prefix=os.path.basename( outputSwix ) )
      manifest = createManifest( tempDir, rpms )
      filesToZip = [manifest] + rpms

      if info:
         pass # TODO: If YAML file, verify.

      # '-0' means 'no compression'.
      # '-j' means 'use basenames'.
      subprocess.check_call( f'zip -0 -j {outputSwix}'.split() + filesToZip )
   except Exception as e:
      sys.exit( f'Error occurred during generation of SWIX file: {e}\n' )
   finally:
      shutil.rmtree( tempDir, ignore_errors=True )

def parseCommandArgs( args ):
   parser = argparse.ArgumentParser( prog='swix create' )
   add = parser.add_argument
   add( 'outputSwix', metavar='OUTFILE.swix',
        help='Name of output file' )
   add( 'rpms', metavar='PACKAGE.rpm', type=str, nargs='+',
        help='An RPM to add to the swix' )
   add( '-f', '--force', action='store_true',
        help='Overwrite OUTFILE.swix if it already exists' )
   add( '-i', '--info', metavar='manifest.yaml', action='store', type=str,
        help='Location of manifest.yaml file to add metadata to swix' )
   return parser.parse_args( args )

def main():
   args = parseCommandArgs( sys.argv[1:] )
   create( **args.__dict__ )

if __name__ == '__main__':
   main()
