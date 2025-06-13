#!/usr/bin/env python3
# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import os
import base64
import binascii
import hashlib
import tempfile
import typer
import shutil
import subprocess
import sys
import zipfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from pathlib import Path
from typing import Annotated, Optional

from switools import crc32collision
from switools import verify
from switools import signaturelib
from switools.callbacks import _path_exists_callback

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
   ERROR_NO_SIGNATURE_FILE_PROVIDED = 6
   ERROR_NO_SIGNING_SERVICE = 7
   ERROR_SIGNING_SERVICE_FAILED = 8
   ERROR_SIGNATURE_INSERTION_FAILED = 9
   ERROR_SIGNATURE_EXTRACTION_FAILED = 10
   INTERNAL_ERROR = 11

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

def prepareSwiHandler( swi, outfile, size, force ):
   hexdigest = prepareSwi( swi=swi, outfile=outfile, forceSign=force,
                           size=size )
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
         subprocess.check_call( [ 'zip', '-dq', swiFile,
                                  signaturelib.getSigFileName( swiFile ) ] )

   # Add null signature to SWI
   # Use run-of-the-mill /usr/bin/zip, so signatures can be extracted with unzip and
   # re-inserted with zip (without changing the version-required-to-extract meta
   # file info (zipFile has 2.0, zip has 1.0) and thus corrupting the signature)
   data = '\000' * size
   with tempfile.TemporaryDirectory( prefix="swi-nullsig-" ) as tmpDir:
      sigFileName = signaturelib.getSigFileName( swiFile )
      with open( "%s/%s" % ( tmpDir, sigFileName ), "w" ) as f:
         f.write( data )
      insertSignature( swiFile, [ sigFileName ], tmpDir )

   # Return SHA-256 hash of null SWI
   nullSwiHash = generateHash( swiFile, 'SHA-256' )
   return nullSwiHash

def signSwiHandler( swi, signingCertFile, rootCaFile, signatureFile, signingKeyFile ):
   with tempfile.TemporaryDirectory( prefix="swi-signature-" ) as workDir:
      signSwiAll( workDir, swi, signingCertFile, rootCaFile, signatureFile, signingKeyFile )
      print( 'SWI/X file %s successfully signed and verified.' % swi )

def runCmd( cmd, workDir=None ):
   try:
      subprocess.check_call( cmd, cwd=workDir )
   except subprocess.CalledProcessError:
      return False
   return True

def insertSignature( swi, sigFileNames, workDir ):
   cmd = [ "zip", "-q", "-0", "-X", os.path.abspath( swi ) ]
   cmd = cmd + sigFileNames
   if not runCmd( cmd, workDir ):
      msg = "Error: Cannot insert signature file(s) '%s' into '%s'" % ( sigFileNames, swi )
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_SIGNATURE_INSERTION_FAILED, msg )

def extractSignature( swi, destFile ):
   # We use zip instead of zipfile.py because zipfile does not honor the timestsamp
   sigFn = signaturelib.SWI_SIG_FILE_NAME
   destDir = os.path.dirname( destFile )
   cmd = [ "unzip", "-o", "-q", os.path.abspath( swi ), sigFn ]
   if not runCmd( cmd, destDir ):
      msg = "Error: Cannot extract signature file %s from  %s" % ( sigFn, swi )
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_SIGNATURE_EXTRACTION_FAILED, msg )
   os.rename( "%s/%s" % ( destDir, sigFn ), destFile )

# get signature from remote signing server
def getSignatureFile( swi, signatureFile ):
   serviceName = 'swi-signing-service'
   serviceBinary = shutil.which( serviceName )
   if not serviceBinary:
      msg = "Error: signing service '%s' not found" % serviceName
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_NO_SIGNING_SERVICE, msg )

   sha256 = prepareSwi( swi=swi, outfile=None, forceSign=True )
   print( "%s sha256: %s" % ( os.path.basename( swi ), sha256 ) )
   cmd = [ "swi-signing-service", sha256, signatureFile ]
   if not runCmd( cmd, "/tmp" ):
      msg = "Error: signing-server '%s' failed" % serviceBinary
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_SIGNING_SERVICE_FAILED, msg )

def signSwiAll( workDir, swi, signingCertFile, rootCaFile, signatureFile=None, signingKeyFile=None ):
   # Sub-images ("optimizations") are extracted to /tmp. The utility 'swadapt' is
   # handling that extraction. swadapt is found inside the image itself and is a
   # statically linked i386 binary.
   # Make sure the image we got is a swi file
   if not signaturelib.checkIsSwiFile( swi ):
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_NOT_A_SWI,
                              "Error: '%s' does not look like an EOS image" % swi )

   optims = signaturelib.getOptimizations( swi, workDir )
   if optims is None or len( optims ) == 1 or "DEFAULT" in optims:
      # legacy case of a single rootfs image
      # maybe need to use a remote signing service (new feature in v1.2)
      if not signatureFile and not signingKeyFile:
         signatureFile = "%s/sig" % workDir
         getSignatureFile( swi, signatureFile ) # never returns in case of fail
      if not signatureFile and not signingKeyFile:
         msg = ( 'Error: without signing key we need a signature file: '
                 'run "swi-signature prepare" first and have the digest it prints '
                 'signed and passed to this command.' )
         raise SwiSignException( SWI_SIGN_RESULT.ERROR_NO_SIGNATURE_FILE_PROVIDED, msg )
      if not signatureFile and signingKeyFile:
         sha256 = prepareSwi( swi=swi, outfile=None, forceSign=True )
         print( "%s sha256: %s" % ( os.path.basename( swi ), sha256 ) )
      # insert the signatureFile into the swi, or use the signing key to create the signatureFile first
      return signSwi( swi, signingCertFile, rootCaFile,
                      signatureFile=signatureFile, signingKeyFile=signingKeyFile )

   print( "Optimizations in %s: %s" % ( swi, " ".join( optims ) ) )
   if not signaturelib.extractSwadapt( swi, workDir ):
      raise SwiSignException( SWI_SIGN_RESULT.INTERNAL_ERROR,
                              "Internal Error: could not extract swadapt utility from image" )
   optimSigFiles = []
   for optim in optims:
      optimImage = "%s/%s.swi" % ( workDir, optim )
      # Adapt swi (extract an optimized image)
      if not signaturelib.adaptSwi( swi, optimImage, optim, workDir ):
         msg = "Error: failed to extract optimization '%s' from image '%s' to '%s'" % (
                  optim, swi, optimImage )
         raise SwiSignException( SWI_SIGN_RESULT.INTERNAL_ERROR, msg )
      if not signingKeyFile: # need to use a remote signing service
         signatureFile = "%s/sig" % workDir
         getSignatureFile( optimImage, signatureFile ) # never returns in case of fail
      else:
         sha256 = prepareSwi( swi=optimImage, outfile=None, forceSign=True )
         print( "%s sha256: %s" % ( optim, sha256 ) )
      # Sign optimized swi using provided key or provided full fledged signature file
      signSwi( optimImage, signingCertFile, rootCaFile,
               signatureFile=signatureFile, signingKeyFile=signingKeyFile )

      # Extract the signature from the optim and call it <optim>.sig
      optimSigFile = "%s.signature" % optim
      optimSigPath = "%s/%s" % ( workDir, optimSigFile )
      optimSigFiles.append( os.path.basename( optimSigPath ) )
      extractSignature( optimImage, optimSigPath )

      os.remove( optimImage )

   # update the source swi with the signatures of its "baby" swis (optims)
   print( "Adding signature files to %s: %s" % ( swi, " ".join( optimSigFiles ) ) )
   insertSignature( swi, optimSigFiles, workDir )

   # And now sign the mother of all images
   sha256 = prepareSwi( swi=swi, outfile=None, forceSign=True )
   print( "%s sha256: %s" % ( os.path.basename( swi ), sha256 ) )
   if not signingKeyFile: # need to use a remote signing service
      cmd = [ "swi-signing-service", sha256, "%s/sig" % workDir ]
      if not runCmd( cmd, workDir ):
         msg = "Error: signing-server failed"
         raise SwiSignException( SWI_SIGN_RESULT.ERROR_SIGNING_SERVICE_FAILED, msg )
   signSwi( swi, signingCertFile, rootCaFile,
            signatureFile=signatureFile, signingKeyFile=signingKeyFile )

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
      with open(signingKeyFile, "rb") as key_file:
         private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
         )
      hashAlg = hashes.SHA256()
      hasher = hashes.Hash( hashAlg )
      with open( swi, 'rb' ) as swiFile:
         while True:
            data = swiFile.read( 2**20 )
            if not data:
               break
            hasher.update( data )
         digest = hasher.finalize()
         signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            utils.Prehashed( hashAlg ),
         )
      signature = base64.b64encode( signature ).decode()

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
   success = verify.verifySwi( swi, rootCA=rootCaFile )
   if success != SWI_SIGN_RESULT.SUCCESS:
      message = 'Error: Verification on the signed SWI/X failed.'
      raise SwiSignException( SWI_SIGN_RESULT.ERROR_FAIL_VERIFICATION, message )


app = typer.Typer(add_completion=False)

@app.command(name="prepare")
def _prepare(
   swi_file: Annotated[Path, typer.Argument(help="Path of the SWI/X to prepare for signing.", callback=_path_exists_callback)],
   outfile: Annotated[Optional[Path], typer.Option("--outfile", help="Path to save SWI/X with null signature, if not replacing the input SWI/X.", callback=_path_exists_callback)] = None,
   size: Annotated[Optional[int], typer.Option("--size", help="Size of null signature to add.")] = SWI_SIGNATURE_MAX_SIZE,
   force: Annotated[Optional[bool], typer.Option("--force-sign", help="Force signing the SWI/X if it's already signed.")] = False,
):
   """
   Prepare an Arista SWI/X for signing.
   Check SWI/X for existing signature, add a null signature.
   """
   try:
      prepareSwiHandler(swi_file, outfile, size, force)
   except ( IOError, BIO.BIOError, EVP.EVPError ) as e:
      print( e, file=sys.stderr )
      exit( SWI_SIGN_RESULT.ERROR_INPUT_FILES )
   except SwiSignException as e:
      print( e, file=sys.stderr )
      exit( e.code )
   exit( SWI_SIGN_RESULT.SUCCESS )

@app.command(name="sign")
def _sign(
   swi_file: Annotated[Path, typer.Argument(help="Path of the SWI/X to sign.", callback=_path_exists_callback)],
   certificate: Annotated[Path, typer.Argument(help="Path of the signing certificate.", callback=_path_exists_callback)],
   root_certificate: Annotated[Path, typer.Argument(help="Path of the root certificate of signing certificate to verify against.", callback=_path_exists_callback)],
   signature_file: Annotated[Optional[Path], typer.Option("--signature", help="Path of base64-encoded SHA-256 signature file of EOS.swi or swix, signed by signing cerificate.", callback=_path_exists_callback)] = None,
   signing_key_file: Annotated[Optional[Path], typer.Option("--key", help="Path of signing key, used to generate the signature.", callback=_path_exists_callback)] = None,
):
   """
   Sign an Arista SWI/X.
   The SWI/X must have a null signature, which can be generated with "prepare" option.
   """
   if signature_file and signing_key_file:
      raise typer.BadParameter("Cannot specify both --signature and --key")

   try:
      signSwiHandler(swi_file, certificate, root_certificate, signature_file, signing_key_file)
   except ( IOError, BIO.BIOError, EVP.EVPError ) as e:
      print( e, file=sys.stderr )
      exit( SWI_SIGN_RESULT.ERROR_INPUT_FILES )
   except SwiSignException as e:
      print( e, file=sys.stderr )
      exit( e.code )
   exit( SWI_SIGN_RESULT.SUCCESS )

if __name__ == "__main__":
   app()
