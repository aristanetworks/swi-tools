#!/usr/bin/env python3
# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

from __future__ import print_function, absolute_import

import argparse
import base64
import binascii
import os
from pkg_resources import resource_string
import zipfile
from M2Crypto import X509

from . import signaturelib

ROOT_CA_FILE_NAME = 'ARISTA_ROOT_CA.crt'
ROOT_CA = resource_string( __name__, ROOT_CA_FILE_NAME )

class SwiSignature:
   def __init__( self ):
      self.version = ""
      self.hashAlgo = ""
      self.cert = ""
      self.signature = ""
      self.offset = 0
      self.size = 0

   def updateFields( self, sigFile ):
      """ Update the fields of this SwiSignature with the file object
      @sigFile, a new-line-delimited file with key-value
      pairs in the form of key:value. For example:
      key1:value1
      key2:value2
      etc. """
      for line in sigFile:
         data = line.decode( "utf-8", "backslashreplace" ).split( ':' )
         if ( len( data ) == 2 ):
            if data[ 0 ] == 'Version':
               self.version = data[ 1 ].strip()
            elif data[ 0 ] == 'HashAlgorithm':
               self.hashAlgo = data[ 1 ].strip()
            elif data[ 0 ] == 'IssuerCert':
               self.cert = base64Decode( data[ 1 ].strip() )
            elif data[ 0 ] == 'Signature':
               self.signature = base64Decode( data [ 1 ].strip() )
         else:
            print( 'Unexpected format for line in swi[x]-signature file: %s' % line )

class VERIFY_SWI_RESULT:
   SUCCESS = 0
   ERROR_SIGNATURE_FILE = 3
   ERROR_VERIFICATION = 4
   ERROR_HASH_ALGORITHM = 5
   ERROR_SIGNATURE_FORMAT = 6
   ERROR_NOT_A_SWI = 7
   ERROR_CERT_MISMATCH = 8
   ERROR_INVALID_SIGNING_CERT = 9
   ERROR_INVALID_ROOT_CERT = 10

VERIFY_SWI_MESSAGE = { 
   VERIFY_SWI_RESULT.SUCCESS: "SWI/X verification successful.",
   VERIFY_SWI_RESULT.ERROR_SIGNATURE_FILE: "SWI/X is not signed." ,
   VERIFY_SWI_RESULT.ERROR_VERIFICATION: "SWI/X verification failed.",
   VERIFY_SWI_RESULT.ERROR_HASH_ALGORITHM: "Unsupported hash algorithm for SWI/X" \
                                           " verification.",
   VERIFY_SWI_RESULT.ERROR_SIGNATURE_FORMAT: "Invalid SWI/X signature file.",
   VERIFY_SWI_RESULT.ERROR_NOT_A_SWI: "Input does not seem to be a swi/x image.",
   VERIFY_SWI_RESULT.ERROR_CERT_MISMATCH: "Signing certificate used to sign SWI/X" \
                                          " is not signed by root certificate.",
   VERIFY_SWI_RESULT.ERROR_INVALID_SIGNING_CERT: "Signing certificate is not a" \
                                                 " valid certificate.",
   VERIFY_SWI_RESULT.ERROR_INVALID_ROOT_CERT: "Root certificate is not a" \
                                              " valid certificate.",
}

class X509CertException( Exception ):
   def __init__( self, code ):
      self.code = code
      message = VERIFY_SWI_MESSAGE[ code ]
      super( X509CertException, self ).__init__( message )

def getSwiSignatureData( swiFile ):
   try:
      swiSignature = SwiSignature()
      with zipfile.ZipFile( swiFile, 'r' ) as swi:
         sigInfo = swi.getinfo( signaturelib.getSigFileName( swiFile ) )
         with swi.open( sigInfo, 'r' ) as sigFile:
            # Get offset from our current location before processing sigFile
            swiSignature.offset = sigFile._fileobj.tell()
            swiSignature.size = sigInfo.compress_size
            swiSignature.updateFields( sigFile )
            return swiSignature
   except KeyError:
      # Occurs if SIG_FILE_NAME is not in the swi (the SWI is not
      # signed properly)
      return None

def verifySignatureFormat( swiSignature ):
   # Check that the signing cert, hash algorithm, and signatures are valid
   return ( len( swiSignature.cert ) != 0 and 
            len( swiSignature.hashAlgo ) != 0 and
            len( swiSignature.signature ) != 0 )

def base64Decode( text ):
   try:
      return base64.standard_b64decode( text )
   except ( binascii.Error, TypeError ):
      return ""

def loadSigningCert( swiSignature ):
   # Read signing cert from memory and load it as an X509 cert object
   try:
      signingCert = X509.load_cert_string( swiSignature.cert )
      return signingCert
   except X509.X509Error:
      raise X509CertException( VERIFY_SWI_RESULT.ERROR_INVALID_SIGNING_CERT )

def signingCertValid( signingCertX509, rootCAFile ):
   # Validate cert used to sign SWI with root CA
   try:
      rootCa = X509.load_cert_string( ROOT_CA )
      if rootCAFile != ROOT_CA_FILE_NAME:
         rootCa = X509.load_cert( rootCAFile )
   except X509.X509Error:
      raise X509CertException( VERIFY_SWI_RESULT.ERROR_INVALID_ROOT_CERT )
   result = signingCertX509.verify( rootCa.get_pubkey() )
   if result == 1:
      return VERIFY_SWI_RESULT.SUCCESS
   else:
      return VERIFY_SWI_RESULT.ERROR_CERT_MISMATCH
      
def getHashAlgo( swiSignature ):
   hashAlgo = swiSignature.hashAlgo
   # For now, we always use SHA-256
   if hashAlgo == 'SHA-256':
      return 'sha256'
   return None

def swiSignatureValid( swiFile, swiSignature, signingCertX509 ):
   hashAlgo = getHashAlgo( swiSignature )
   if hashAlgo is None:
      return VERIFY_SWI_RESULT.ERROR_HASH_ALGORITHM

   # Verify the swi against the signature in swi-signature
   offset = 0
   BLOCK_SIZE = 65536
   pubkey = signingCertX509.get_pubkey()
   pubkey.reset_context( md=hashAlgo )
   # Begin reading the data to verify
   pubkey.verify_init()
   # Read the swi file into the verification function, up to the swi signature file
   with open( swiFile, 'rb' ) as swi:
      while offset < swiSignature.offset:
         if offset + BLOCK_SIZE < swiSignature.offset:
            numBytes = BLOCK_SIZE
         else:
            numBytes = swiSignature.offset - offset
         pubkey.verify_update( swi.read( numBytes ) )
         offset += numBytes
      # Now that we're at the swi-signature file, read zero's into the verification
      # function up to the size of the swi-signature file.
      pubkey.verify_update( b'\000' * swiSignature.size )

      # Now jump to the end of the swi-signature file and read the rest of the swi
      # file into the verification function
      swi.seek( swiSignature.size, os.SEEK_CUR )
      for block in iter( lambda: swi.read( BLOCK_SIZE ), b'' ):
         pubkey.verify_update( block )
   # After reading the swi file and skipping over the swi signature, check that the
   # data signed with pubkey is the same as signature in the swi-signature.
   result = pubkey.verify_final( swiSignature.signature )
   if result == 1:
      return VERIFY_SWI_RESULT.SUCCESS
   else:
      return VERIFY_SWI_RESULT.ERROR_VERIFICATION

def verifySwi( swi, rootCA=ROOT_CA_FILE_NAME ):
   try:
      if not zipfile.is_zipfile( swi ):
         return VERIFY_SWI_RESULT.ERROR_NOT_A_SWI
      swiSignature = getSwiSignatureData( swi )
      if swiSignature is None:
         return VERIFY_SWI_RESULT.ERROR_SIGNATURE_FILE
      if not verifySignatureFormat( swiSignature ):
         return VERIFY_SWI_RESULT.ERROR_SIGNATURE_FORMAT
      signingCert = loadSigningCert( swiSignature )
      result = signingCertValid( signingCert, rootCA )
      if result != VERIFY_SWI_RESULT.SUCCESS:
         # Signing cert invalid
         return result
      result = swiSignatureValid( swi, swiSignature, signingCert )
      if result != VERIFY_SWI_RESULT.SUCCESS:
         return result
      else:
         return VERIFY_SWI_RESULT.SUCCESS
   except IOError as e:
      print( e )
      return VERIFY_SWI_RESULT.ERROR_VERIFICATION
   except X509CertException as e:
      return e.code

def main():
   helpText = "Verify Arista SWI image or SWIX extension"
   parser = argparse.ArgumentParser( description=helpText, 
               formatter_class=argparse.ArgumentDefaultsHelpFormatter )
   parser.add_argument( "swi_file", metavar="EOS.swi[x]", help="SWI/X file to verify" )
   parser.add_argument( "--CAfile", default=ROOT_CA_FILE_NAME,
                        help="Root certificate to verify against." )
                        
   args = parser.parse_args()
   swi = args.swi_file
   rootCA = args.CAfile

   retCode = verifySwi( swi, rootCA )
   print( VERIFY_SWI_MESSAGE[ retCode ] )
   exit( retCode )

if __name__ == "__main__":
   main()
