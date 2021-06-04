#!/usr/bin/env python3
# Copyright ( c ) 2021 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

'''
This module is responsible for packaging a SWIX file.
'''

import argparse
import hashlib
import jsonschema
import os
import shutil
import subprocess
import sys
import tempfile
import yaml

manifestYamlName = 'manifest.yaml'

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

def createManifestTxt( tempDir, rpms ):
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

def verifyManifestYaml( filename, rpms ):
   '''
   Validate the contents of the manifest.yaml file.
   Currently, we just validate the structure.
   '''
   # TODO: Replace with an actual list.
   sampleEosVersions = ( '4.26.0.1F',
                         '4.26.0F',
                         '4.25.4M',
                         '4.25.3.1M',
                         '4.25.3M',
                         '4.25.2F',
                         '4.25.1.1F',
                         '4.25.1F',
                         '4.25.0F',
                       )
   supportedManifestVersions = { 1.0 }
   try:
      with open( filename ) as f:
         manifest = yaml.safe_load( f.read() )

      key = 'metadataVersion'
      version = manifest[ key ]
      assert version in supportedManifestVersions

      with open( f'swixtools/schema{version}.json' ) as f:
         schema = yaml.safe_load( f.read() )

      jsonschema.validate( manifest, schema )
   except EnvironmentError as e:
      sys.exit( f'Error opening {filename}: {e}' )
   except yaml.YAMLError as e:
      sys.exit( f'Error parsing {filename}: {e}' )
   except KeyError:
      sys.exit( f'{key!r} not found in {filename}!' )
   except AssertionError:
      supported = ', '.join( str( v ) for v in supportedManifestVersions )
      sys.exit( f'Manifest version {version!r} is not supported\n'
                f'Supported versions: {supported}' )
   except jsonschema.exceptions.ValidationError as e:
      sys.exit( f'{e}' )

def create( outputSwix=None, info=None, rpms=None, force=False ):
   '''
   Create a SWIX file named `outputSwix` given a list of RPMs.
   '''
   dealWithExistingOutputFile( outputSwix, force )
   try:
      tempDir = tempfile.mkdtemp( suffix='.tempDir',
                                  prefix=os.path.basename( outputSwix ) )
      manifest = createManifestTxt( tempDir, rpms )
      filesToZip = [ manifest ] + rpms

      if info:
         # Copy manifest.yaml to temp dir; does two things:
         # - Ensures file is correctly named,
         # - Fails if file does not exist.
         copy = os.path.join( tempDir, manifestYamlName )
         shutil.copyfile( info, copy )
         verifyManifestYaml( copy, rpms )
         filesToZip.append( copy )

      # '-0' means 'no compression'.
      # '-j' means 'use basenames'.
      subprocess.check_call( [ 'zip', '-0', '-j', outputSwix ] + filesToZip )
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
        help='An RPM to add to the SWIX' )
   add( '-f', '--force', action='store_true',
        help='Overwrite OUTFILE.swix if it already exists' )
   add( '-i', '--info', metavar=manifestYamlName, action='store', type=str,
        help=f'Location of {manifestYamlName} file to add metadata to SWIX' )
   return parser.parse_args( args )

def main():
   args = parseCommandArgs( sys.argv[1:] )
   create( **args.__dict__ )

if __name__ == '__main__':
   main()
