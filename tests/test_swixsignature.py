# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import unittest
import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path

from switools import signature
from switools import verify

from . import MockSigningServer

SIG_FILE_NAME = 'swix-signature'

class TestSwiSignature( unittest.TestCase ):

    def setUp( self ):
        self.test_dir = tempfile.mkdtemp()
        self.test_swix = self._makeTestSwix( 'EOS-extension.swix' )
        self.root_crt = self._writeFile( 'root.crt', 
                                         MockSigningServer.MOCK_ROOT_CERT )
        self.signing_crt = self._writeFile( 'signing.crt', 
                                            MockSigningServer.MOCK_SIGNING_CERT )
        self.signing_key = self._writeFile( 'signing.key', 
                                            MockSigningServer.MOCK_SIGNING_KEY )

    def tearDown( self ):
        shutil.rmtree( self.test_dir )

    def _writeFile( self, filename, contents ):
        path = Path( self.test_dir, filename )
        with open( path, 'w' ) as f:
            f.write( contents )
        return path

    def _makeTestSwix( self, filename ):
        path = Path( self.test_dir, filename )
        with zipfile.ZipFile( path, 'w' ) as swix:
            swix.writestr( 'manifest', 'some rpms names here' )
        return path

    def _validateNullSig( self, filename, size=8192, exists=True ):
        with zipfile.ZipFile( filename, 'r', zipfile.ZIP_STORED ) as swix:
            try:
                sigFileInfo = swix.getinfo( SIG_FILE_NAME )
            except KeyError:
                self.assertFalse( exists )
            else:
                fileSize = sigFileInfo.file_size
                self.assertEqual( fileSize, size )
                self.assertTrue( exists )

    def _generateHash( self, filename, blockSize=65536 ):
        sha256sum = hashlib.sha256()
        with open( filename, 'rb' ) as swixFile:
            for block in iter( lambda: swixFile.read( blockSize ), b'' ):
                sha256sum.update( block )
        return sha256sum.hexdigest()

    def _verifySignature( self, filename ):
        retCode = verify.verifySwi( filename, rootCA=self.root_crt )
        self.assertEqual( retCode, 0 )

    def test_prepare_return_hexdigest( self ):
        hexdigest = signature.prepareSwi( self.test_swix )
        actualHash = self._generateHash( self.test_swix ) 
        self.assertEqual( hexdigest, actualHash )

    def test_prepare_with_outfile( self ):
        outfileName = 'EOS_null_sig.swix'
        outfile = Path( self.test_dir, outfileName )
        signature.prepareSwi( self.test_swix, outfile )
        self._validateNullSig( outfile )
        self._validateNullSig( self.test_swix, exists=False )

    def test_prepare_with_size( self ):
        testSize = 9000
        signature.prepareSwi( self.test_swix, size=testSize )
        self._validateNullSig( self.test_swix, size=testSize )

    def test_prepare_already_signed( self ):
        with zipfile.ZipFile( self.test_swix, 'a' ) as swix:
            swix.writestr( SIG_FILE_NAME, 'random signature' )
        with self.assertRaises( signature.SwiSignException ):
            signature.prepareSwi( self.test_swix )

    def test_prepare_already_signed_force( self ):
        with zipfile.ZipFile( self.test_swix, 'a' ) as swix:
            swix.writestr( SIG_FILE_NAME, 'random signature' )
        signature.prepareSwi( self.test_swix, forceSign=True )
        self._validateNullSig( self.test_swix )

    def test_sign_without_prepare( self ):
        with self.assertRaises( signature.SwiSignException ):
            signature.signSwi( self.test_swix, self.signing_crt, self.root_crt )

    def test_sign_with_key( self ):
        signature.prepareSwi( self.test_swix )
        signature.signSwi( self.test_swix, self.signing_crt, self.root_crt,
                              signingKeyFile=self.signing_key )
        self._verifySignature( self.test_swix )

    def test_sign_with_signature( self ):
        signature.prepareSwi( self.test_swix )
        mock_signature = MockSigningServer.getTestSignature( self.test_swix )
        sigFile = self._writeFile( 'signature.sig', mock_signature )
        signature.signSwi( self.test_swix, self.signing_crt, self.root_crt,
                              signatureFile=sigFile )
        self._verifySignature( self.test_swix )

    def test_sign_with_bad_signature( self ):
        signature.prepareSwi( self.test_swix )
        not_base64_signature = 'a'
        sigFile = self._writeFile( 'signature.sig', not_base64_signature )
        with self.assertRaises( signature.SwiSignException ):
            signature.signSwi( self.test_swix, self.signing_crt, self.root_crt,
                                  signatureFile=sigFile )

    def test_sign_and_verify_with_wrong_root_crt( self ):
        signature.prepareSwi( self.test_swix )
        with self.assertRaises( signature.SwiSignException ):
            signature.signSwi( self.test_swix, self.signing_crt, self.signing_crt,
                                  signingKeyFile=self.signing_key )

    def test_sign_with_size_and_outfile( self ):
        testSize = 9001
        outfileName = 'EOS_null_sig.swix'
        outfile = Path( self.test_dir, outfileName )
        signature.prepareSwi( self.test_swix, size=testSize, 
                                 outfile=outfile )
        signature.signSwi( outfile, self.signing_crt, self.root_crt,
                              signingKeyFile=self.signing_key )
        self._verifySignature( outfile )

    def test_signature_bigger_than_null_sig( self ):
        signature.prepareSwi( self.test_swix )
        bigCertFile = self._writeFile( 'bigCrt.crt', 'a' * 9000 )
        with self.assertRaises( signature.SwiSignException ):
            signature.signSwi( self.test_swix, bigCertFile, self.root_crt,
                                  signingKeyFile=self.signing_key )

if __name__ == '__main__':
    unittest.main()
