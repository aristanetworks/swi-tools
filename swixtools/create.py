#!/usr/bin/env python3
# Copyright ( c ) 2021 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

'''
This module is responsible for packaging a SWIX file.
'''

import argparse
import functools
import hashlib
import jsonschema
import os
import pyparsing
import shutil
import subprocess
import sys
import tempfile
import yaml
from pkg_resources import resource_string

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

def createManifestFile( tempDir, rpms ):
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
         fprint = functools.partial( print, file=manifest )
         fprint( 'format: 1' )
         fprint( f'primaryRpm: {basename( rpms[ 0 ] )}' )
         for rpm in rpms:
            fprint( f'{basename( rpm )}-sha1: {sha1sum( rpm )}' )
   except Exception as e:
      sys.exit( f'{manifestFileName}: {e}\n' )

   return manifestFileName

def validateVersions1_0( versionStrings ):
   '''
   Validate EOS version strings like "4.3.21".
   Other valid strings: '4.22.3*', '4.14.5FX*',
                        '4.14.5.1*', '4.19*',
                        '4.22.{3-12}', '4.{22-23}.1',
                        '4.22.{3-$}', '4.{19-21}.{3-5}*',
                        '4.22.{3-12}*', '4.22.3, 4.21.3*, 4.20.{3-12}*'
   '''
   # Define individual parts of the syntax. A number is consecutive digits.
   number = pyparsing.Word( pyparsing.nums )
   # End of a number range can be a number or '$', meaning 'latest version'.
   rangeEnd = number ^ '$'
   # A range of numbers: '{1-5}', '{7-$}', etc.
   numRange = '{' + number + '-' + rangeEnd + '}'
   # Minor and patch are a number or a range.
   minor = number ^ numRange

   # Define the syntax: Start with a major version like '4'.
   singleVersionSyntax = number
   # Then '.' and maybe minor and patch, each as a number or range.
   singleVersionSyntax += pyparsing.ZeroOrMore( '.' + minor )
   # Then letters like 'FX'.
   singleVersionSyntax += pyparsing.Optional( pyparsing.Word( pyparsing.alphas ) )
   # Star means 'anything' and can only be used in the end.
   singleVersionSyntax += pyparsing.Optional( '*' )
   # A version string could be several versions, separated by a comma.
   syntax = singleVersionSyntax + pyparsing.ZeroOrMore( ',' + singleVersionSyntax )

   for v in versionStrings:
      try:
         syntax.parseString( v, parseAll=True )
      except pyparsing.ParseException as e:
         # Error doesn't include string, so repackage it.
         raise pyparsing.ParseException( f'Unable to parse {v!r}\n{e}' )

validatorFuncs = {
   # Caveat: `1` and `1.0` map the same.
   1.0: validateVersions1_0,
}

def validateVersions( version, versionStrings ):
   return validatorFuncs[ version ]( versionStrings )

def verifyManifestYaml( filename, rpms ):
   '''
   Validate the contents of the manifest.yaml file.
   Currently, we just validate the structure.
   '''
   # TODO: Print version/compatible RPMs table.
   supportedManifestVersions = { 1.0 }
   try:
      with open( filename ) as f:
         manifest = yaml.safe_load( f.read() )

      key = 'metadataVersion'
      version = manifest[ key ]
      assert version in supportedManifestVersions

      schema = resource_string( __name__, f'static/schema{version}.json' )
      jsonschema.validate( manifest, yaml.safe_load( schema ) )
      versionStrings = manifest.get( 'version' )
      if versionStrings:
         validateVersions( version, ( list( v )[ 0 ] for v in versionStrings ) )
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
      sys.exit( f'Manifest validation error: {e}' )
   except pyparsing.ParseException as e:
      sys.exit( f'Version strings validation error: {e}' )

def create( outputSwix=None, manifestYaml=None, rpms=None, force=False ):
   '''
   Create a SWIX file named `outputSwix` given a list of RPMs.
   '''
   dealWithExistingOutputFile( outputSwix, force )
   try:
      tempDir = tempfile.mkdtemp( suffix='.tempDir',
                                  prefix=os.path.basename( outputSwix ) )
      manifestFilename = createManifestFile( tempDir, rpms )
      filesToZip = [ manifestFilename ] + rpms

      if manifestYaml:
         # Copy manifest.yaml to temp dir; does two things:
         # - Ensures file is correctly named,
         # - Fails if file does not exist.
         copy = os.path.join( tempDir, manifestYamlName )
         shutil.copyfile( manifestYaml, copy )
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
        dest='manifestYaml',
        help=f'Location of {manifestYamlName} file to add metadata to SWIX' )
   return parser.parse_args( args )

def main():
   args = parseCommandArgs( sys.argv[1:] )
   create( **args.__dict__ )

if __name__ == '__main__':
   main()
