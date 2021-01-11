# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import unittest
import hashlib
import os
import shutil
import tempfile
import zipfile

from switools import swisignature
from switools import verifyswi

from . import MockSigningServer

SIG_FILE_NAME = 'swi-signature'

class TestSwiSignature( unittest.TestCase ):

    def setUp( self ):
        self.test_dir = tempfile.mkdtemp()
        self.test_swi = self._makeTestSwi( 'EOS.swi' )
        self.root_crt = self._writeFile( 'root.crt', 
                                         MockSigningServer.MOCK_ROOT_CERT )
        self.signing_crt = self._writeFile( 'signing.crt', 
                                            MockSigningServer.MOCK_SIGNING_CERT )
        self.signing_key = self._writeFile( 'signing.key', 
                                            MockSigningServer.MOCK_SIGNING_KEY )

    def tearDown( self ):
        shutil.rmtree( self.test_dir )

    def _writeFile( self, filename, contents ):
        path = os.path.join( self.test_dir, filename )
        with open( path, 'w' ) as f:
            f.write( contents )
        return path

    def _makeTestSwi( self, filename ):
        path = os.path.join( self.test_dir, filename )
        with zipfile.ZipFile( path, 'w' ) as swi:
            swi.writestr( 'version', '4.21.0F' )
        return path

    def _validateNullSig( self, filename, size=8192, exists=True ):
        with zipfile.ZipFile( filename, 'r', zipfile.ZIP_STORED ) as swi:
            try:
                sigFileInfo = swi.getinfo( SIG_FILE_NAME )
            except KeyError:
                self.assertFalse( exists )
            else:
                fileSize = sigFileInfo.file_size
                self.assertEqual( fileSize, size )
                self.assertTrue( exists )

    def _generateHash( self, filename, blockSize=65536 ):
        sha256sum = hashlib.sha256()
        with open( filename, 'rb' ) as swiFile:
            for block in iter( lambda: swiFile.read( blockSize ), b'' ):
                sha256sum.update( block )
        return sha256sum.hexdigest()

    def _verifySignature( self, filename ):
        retCode = verifyswi.verifySwi( filename, rootCA=self.root_crt )
        self.assertEqual( retCode, 0 )

    def test_prepare_return_hexdigest( self ):
        hexdigest = swisignature.prepareSwi( self.test_swi )
        actualHash = self._generateHash( self.test_swi ) 
        self.assertEqual( hexdigest, actualHash )

    def test_prepare_with_outfile( self ):
        outfileName = 'EOS_null_sig.swi'
        outfile = os.path.join( self.test_dir, outfileName )
        swisignature.prepareSwi( self.test_swi, outfile )
        self._validateNullSig( outfile )
        self._validateNullSig( self.test_swi, exists=False )

    def test_prepare_with_size( self ):
        testSize = 9000
        swisignature.prepareSwi( self.test_swi, size=testSize )
        self._validateNullSig( self.test_swi, size=testSize )

    def test_prepare_already_signed( self ):
        with zipfile.ZipFile( self.test_swi, 'a' ) as swi:
            swi.writestr( SIG_FILE_NAME, 'random signature' )
        with self.assertRaises( swisignature.SwiSignException ):
            swisignature.prepareSwi( self.test_swi )

    def test_prepare_already_signed_force( self ):
        with zipfile.ZipFile( self.test_swi, 'a' ) as swi:
            swi.writestr( SIG_FILE_NAME, 'random signature' )
        swisignature.prepareSwi( self.test_swi, forceSign=True )
        self._validateNullSig( self.test_swi )

    def test_sign_without_prepare( self ):
        with self.assertRaises( swisignature.SwiSignException ):
            swisignature.signSwi( self.test_swi, self.signing_crt, self.root_crt )

    def test_sign_with_key( self ):
        swisignature.prepareSwi( self.test_swi )
        swisignature.signSwi( self.test_swi, self.signing_crt, self.root_crt,
                              signingKeyFile=self.signing_key )
        self._verifySignature( self.test_swi )

    def test_sign_with_signature( self ):
        swisignature.prepareSwi( self.test_swi )
        signature = MockSigningServer.getTestSignature( self.test_swi )
        sigFile = self._writeFile( 'signature.sig', signature )
        swisignature.signSwi( self.test_swi, self.signing_crt, self.root_crt,
                              signatureFile=sigFile )
        self._verifySignature( self.test_swi )

    def test_sign_with_bad_signature( self ):
        swisignature.prepareSwi( self.test_swi )
        not_base64_signature = 'a'
        sigFile = self._writeFile( 'signature.sig', not_base64_signature )
        with self.assertRaises( swisignature.SwiSignException ):
            swisignature.signSwi( self.test_swi, self.signing_crt, self.root_crt,
                                  signatureFile=sigFile )

    def test_sign_and_verify_with_wrong_root_crt( self ):
        swisignature.prepareSwi( self.test_swi )
        with self.assertRaises( swisignature.SwiSignException ):
            swisignature.signSwi( self.test_swi, self.signing_crt, self.signing_crt,
                                  signingKeyFile=self.signing_key )

    def test_sign_with_size_and_outfile( self ):
        testSize = 9001
        outfileName = 'EOS_null_sig.swi'
        outfile = os.path.join( self.test_dir, outfileName )
        swisignature.prepareSwi( self.test_swi, size=testSize, 
                                 outfile=outfile )
        swisignature.signSwi( outfile, self.signing_crt, self.root_crt,
                              signingKeyFile=self.signing_key )
        self._verifySignature( outfile )

    def test_signature_bigger_than_null_sig( self ):
        swisignature.prepareSwi( self.test_swi )
        bigCertFile = self._writeFile( 'bigCrt.crt', 'a' * 9000 )
        with self.assertRaises( swisignature.SwiSignException ):
            swisignature.signSwi( self.test_swi, bigCertFile, self.root_crt,
                                  signingKeyFile=self.signing_key )

if __name__ == '__main__':
    unittest.main()
