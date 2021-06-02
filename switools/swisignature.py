#!/usr/bin/env python3
# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from __future__ import print_function, absolute_import

import argparse
import base64
import binascii
import hashlib
import shutil
import subprocess
import sys
import zipfile
from M2Crypto import BIO, EVP

from . import crc32collision
from . import verifyswi
from . import signaturelib

SIGN_VERSION = 1
SWI_SIGNATURE_MAX_SIZE = 8192
SIGN_HASH = 'SHA-256'

class SwiSignature:
   def __init__( self, size ):
      self.version = SIGN_VERSION
      self.hash = ""
      self.cert = ""
      self.signature = ""
      self.crcpadding = [ 0, 0, 0, 0 ]
      self.offset = 0
      self.size = size

   def __repr__(self):
      data = r''
      data += "HashAlgorithm:" + self.hash + "\n"
      data += "IssuerCert:" + self.cert + "\n"
      data += "Signature:" + self.signature + "\n"
      data += "Version:" + str( self.version ) + "\n"
      crcPadding = "CRCPadding:"
      for byte in self.crcpadding:
         crcPadding += "%c" % (byte & 0xff)
      data += "Padding:"
      # We need to add padding to make the null signature the same length as
      # the actual SWI signature so they will generate the same hash.
      # The padding amount factors in the length of the current signature data,
      # the CRC padding, and the newline character for the padding field.
      paddingAmt = self.size - len( data ) - len( crcPadding ) - 1
      if paddingAmt < 0:
         message = ( 'Input data exceeds size of null signature by %d bytes.'
                     ' Please increase the size of the null signature to'
                     ' at least %d.' ) % ( abs( paddingAmt ), 
                                           self.size - paddingAmt )
         raise SwiSignException( SWI_SIGN_RESULT.ERROR_INPUT_FILES, message )  
      data += "*" * paddingAmt + "\n"
      data += "CRCPadding:" # we add actual crc padding later since it is in bytes
      assert len( data ) == self.size - len( self.crcpadding )
      return data

   def getBytes( self ):
      data = b''
      data += self.__repr__().encode()
      # Add CRC padding
      for byte in self.crcpadding:
         data += b'%c' % ( byte & 0xff )
      return data

class SWI_SIGN_RESULT:
   SUCCESS = 0
   ALREADY_SIGNED = 1
   ERROR_FAIL_VERIFICATION = 2
   ERROR_NO_NULL_SIG = 3
   ERROR_NOT_A_SWI = 4
   ERROR_INPUT_FILES = 5

class SwiSignException( Exception ):
   def __init__( self, code, message ):
      self.code = code
      super( SwiSignException, self ).__init__( message )

def swiSignatureExists( swiFile ):
   if not zipfile.is_zipfile( swiFile ):
      message = 'Input is not a SWI/X file.' 
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_NOT_A_SWI, message )
   with zipfile.ZipFile( swiFile, 'r' ) as swi:
      if signaturelib.getSigFileName( swiFile ) not in swi.namelist():
         return False
      else:
         return True

def getNullSigInfo( swiFile ):
   with zipfile.ZipFile( swiFile, 'r', zipfile.ZIP_STORED ) as swi:
      sigFileInfo = swi.getinfo( signaturelib.getSigFileName( swiFile ) )
      fileSize = sigFileInfo.file_size
      with swi.open( sigFileInfo ) as sigFile:
         offset = sigFile._fileobj.tell()
   return offset, fileSize

def generateHash( swi, hashAlgo, blockSize=65536 ):
   # For now, we always use SHA-256.
   assert hashAlgo == 'SHA-256'
   sha256sum = hashlib.sha256()
   with open( swi, 'rb' ) as swiFile:
      for block in iter( lambda: swiFile.read( blockSize ), b'' ):
         sha256sum.update( block )
   return sha256sum.hexdigest()

def prepareSwiHandler( args ):
   hexdigest = prepareSwi( swi=args.swi, outfile=args.outfile, forceSign=args.force_sign,
                           size=args.size )
   print( hexdigest )

def prepareSwi( swi, outfile=None, forceSign=False, size=SWI_SIGNATURE_MAX_SIZE ):
   swiFile = swi
   if outfile:
      shutil.copyfile( swi, outfile )
      swiFile = outfile
   
   # Check if SWI is signed already
   if swiSignatureExists( swiFile ):
      if not forceSign:
         message = ( 'SWI/X is already signed. Please check the signature with verify-swi command.'
                     ' To re-sign, use the --force-sign option.' )
         raise SwiSignException( SWI_SIGN_RESULT.ALREADY_SIGNED, message )
      else:
         # Force sign. Remove the swi-signature file from the SWI.
         subprocess.check_call( [ 'zip', '-d', swiFile, 
                                  signaturelib.getSigFileName( swiFile ) ] )

   # Add null signature to SWI
   data = '\000' * size
   with zipfile.ZipFile( swiFile, 'a', zipfile.ZIP_STORED ) as swi:
      swi.writestr( signaturelib.getSigFileName( swiFile ), data )

   # Return SHA-256 hash of null SWI
   nullSwiHash = generateHash( swiFile, 'SHA-256' )
   return nullSwiHash

def signSwiHandler( args ):
   swi = args.swi
   signingCertFile = args.certificate
   rootCaFile = args.CAfile
   signatureFile = args.signature
   signingKeyFile = args.key
   signSwi( swi, signingCertFile, rootCaFile, signatureFile, signingKeyFile )
   print( 'SWI/X file %s successfully signed and verified.' % swi )

def signSwi( swi, signingCertFile, rootCaFile, signatureFile=None, signingKeyFile=None ):
   signature = ""
   certificate = ""

   # Make sure SWI has a signature
   if not swiSignatureExists( swi ):
      message = ( 'Error: SWI/X does not have a null signature. Please add one using'
                  ' "swi-signature prepare" first.' )
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_NO_NULL_SIG, message )

   # Figure out signature - either use given signature or generate one with 
   # signing cert/key
   if signatureFile:
      with open( signatureFile, 'r' ) as sigFile:
         signature = sigFile.read().strip()
      # Check signature is valid base64
      try:
         base64.b64decode( signature )
      except ( binascii.Error, TypeError ):
         message = 'Error: Signature not in base64.'
         raise SwiSignException( SWI_SIGN_RESULT.ERROR_INPUT_FILES, message )
   elif signingKeyFile:
      with open( swi, 'rb' ) as swiFile:
         key = EVP.load_key( signingKeyFile )
         key.reset_context( md='sha256' )
         key.sign_init()
         key.sign_update( swiFile.read() )
         signature = base64.b64encode( key.sign_final() ).decode()
   
   # Process signing certificate
   with open( signingCertFile, 'rb' ) as certFile:
      certificate = base64.standard_b64encode( certFile.read().strip() ).decode()

   # Update signature fields
   offset, fileSize = getNullSigInfo( swi )
   swiSignature = SwiSignature( fileSize )
   swiSignature.signature = signature
   swiSignature.cert = certificate
   swiSignature.hash = SIGN_HASH

   # Update crc padding for swiSignature to match the null signature.
   data = '\000' * fileSize
   nullcrc32 = binascii.crc32( data.encode() ) & 0xffffffff
   swiSigCrc32 = binascii.crc32( str( swiSignature ).encode() ) & 0xffffffff
   swiSignature.crcpadding = crc32collision.matchingBytes( nullcrc32, swiSigCrc32 )
   
   # Rewrite the swi-signature in the right place, replacing the null signature
   with open( swi, 'r+b' ) as outfile:
      outfile.seek( offset )
      outfile.write( swiSignature.getBytes() )

   # Verify the signature of the SWI
   success = verifyswi.verifySwi( swi, rootCA=rootCaFile )
   if success != SWI_SIGN_RESULT.SUCCESS:
      message = 'Error: Verification on the signed SWI/X failed.'
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_FAIL_VERIFICATION, message )

def main():
   helpText = "Sign an Arista SWI or SWIX."
   parser = argparse.ArgumentParser( description=helpText )

   # Add options for preparing and signing the SWI
   subparsers = parser.add_subparsers( help="Operations to perform on SWI/X file" )
   parser_prepare = subparsers.add_parser( 'prepare', 
                     help='Check SWI/X for existing signature, add a null signature' )
   parser_sign = subparsers.add_parser( 'sign', 
                     help='Sign the SWI/X. The SWI/X must have a null signature, which'
                          ' can be generated with "prepare" option.' )

   # Options for preparing the SWI
   parser_prepare.add_argument( "swi", metavar="EOS.swi[x]",
                        help="Path of the SWI/X to prepare for signing" )
   parser_prepare.add_argument( "--force-sign", 
                        help="Force signing the SWI/X if it's already signed",
                        action="store_true")
   parser_prepare.add_argument( "--outfile", 
                        help="Path to save SWI/X with null signature, if not"
                             " replacing the input SWI/X" )
   parser_prepare.add_argument( "--size", type=int, default=SWI_SIGNATURE_MAX_SIZE,
                        help="Size of null signature to add (default 8192 bytes)" )
   parser_prepare.set_defaults( func=prepareSwiHandler )

   # Options for signing the SWI
   parser_sign.add_argument( "swi", metavar="EOS.swi[x]",
                        help="Path of the SWI/X to sign." )
   parser_sign.add_argument( "certificate", metavar="SIGNINGCERT.crt",
                        help="Path of signing certificate." )
   parser_sign.add_argument( "CAfile", metavar="ROOTCERT.crt",
                        help="Root certificate of signing certificate to verify against" )
   signingMethod = parser_sign.add_mutually_exclusive_group( required=True )
   signingMethod.add_argument( "--signature", metavar="SIGNATURE.txt",
                        help="Path of base64-encoded SHA-256 signature file of"
                             " EOS.swi or swix, signed by signing cerificate." )
   signingMethod.add_argument( "--key", metavar="SIGNINGKEY.key",
                        help="Path of signing key, used to generate the signature" )

   parser_sign.set_defaults( func=signSwiHandler )

   args = parser.parse_args()
   try:
      args.func( args )
   except ( IOError, BIO.BIOError, EVP.EVPError ) as e:
      print( e )
      exit( SWI_SIGN_RESULT.ERROR_INPUT_FILES )
   except SwiSignException as e:
      print( e )
      exit( e.code )
   except AttributeError as e: # When main is called with no op.
      sys.exit( parser.format_help() )
  
   exit( SWI_SIGN_RESULT.SUCCESS )

if __name__ == '__main__':
   main()
