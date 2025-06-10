# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import unittest
import base64
import shutil
import tempfile
import zipfile
from pathlib import Path

from switools import verify
from switools.verify import VERIFY_SWI_RESULT

from . import MockSigningServer

SIG_FILE_NAME = 'swi-signature'

# Random bad certificate
BAD_SIGNING_CERT = """-----BEGIN CERTIFICATE-----
MIICmzCCAYMCAQAwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UEAwwEY2FwaTAgFw0x
NDExMTMwMDM5MTFaGA8yMTE0MTAyMDAwMzkxMVowFjEUMBIGA1UEAwwLcGV0ZXJw
YW4gMTMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwqhgAs7sgPEgv
jCQDCktqTjqfSBtlfffD3+LELy5dnu3YwU/CRPSzeLAnLLQB8K4wPgCkkrJcJdQV
sCRJ7n5MYibOGA5Up9A0jCFdszlOZWFswCwPrkeg8onj61KT8qcPonw4hpdI2GDr
vFg+lxTN6u+k7R0K63j/7X5aiO1bkmnV9wOOKJOmfulpgiFjWBKi/0zlD4PlQ57O
HivJ+jmVKMZzNfe2jeWuKqGB8k2HJtvg3oleu5vt8m1XcyMqxMCle9J8JYHcfSTs
86q2r+eexkzPoMvAwmaUhQ+JDsaGJE+ZCq4S7JEctyAwBaOqRE3J6n46EcZ/Kfxz
OYAZBKRXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJxn5eDR2QUcbJtCQ3U4VcpE
VgMOcLDzWIazmTvgR3ga3JNJqsHwgSfpZ5oTVAaIn+TFfxLmVT1Mi6XPNz1HdgWM
91YiSiY6PLoAYoUKShZpPqbMIeQUNKC764MH2fC8VpvJlvT9f6Hhq0mwC/GXbiAd
YJhdChI0J5eyqCzT/2Ahmudpk4S25ehCcOEugZRFR46JETSu/yO5XzJmFqa2kFVf
i2rEL8Vw0Qmt9qlsoUwE5AA5toEP2dguBLz2PIb6/uYvMW0DoLqVIyeNKT/C+6ND
mNkSQf6ILPqzfAPhwg7/s9Y7X4UqM1ex0yiryw2iX5LqVkS9rLIBtNsmHoH1Xpw=
-----END CERTIFICATE-----"""

FAKE_SIGNATURE = "MEUCIQCK5BtHiuFn+hoV8GnIICc60AUi1rgKtOtrguIUz4g5/gIgHXT5beCabs\
        hhWhuItZFGEop77TPhaA9ha2eh4FKRd+8="

class TestVerifyBadSignature( unittest.TestCase ):
    def setUp( self ):
        self.test_dir = tempfile.mkdtemp()
        self.root_crt = self._writeFile( 'root.crt', 
                                         MockSigningServer.MOCK_ROOT_CERT )
        self.test_swi = Path( self.test_dir, 'Test.swi' )
        with zipfile.ZipFile( self.test_swi, 'w' ) as swi:
            swi.writestr( 'version', 'SWI_VERSION=4.21.0F' )

    def tearDown( self ):
        shutil.rmtree( self.test_dir )

    def _writeFile( self, filename, contents ):
        path = Path( self.test_dir, filename )
        with open( path, 'w' ) as f:
            f.write( contents )
        return path

    def _addSigToSwi( self, signature ):
        with zipfile.ZipFile( self.test_swi, 'a' ) as swi:
            swi.writestr( SIG_FILE_NAME, signature )

    def _makeSwiSignature( self, signingCert=MockSigningServer.MOCK_SIGNING_CERT,
                           signature=FAKE_SIGNATURE,
                           hashAlgo='SHA-256' ):
        swiSignature = {}
        swiSignature[ 'IssuerCert' ] = base64.standard_b64encode( signingCert.encode() ).decode()
        swiSignature[ 'HashAlgorithm' ] = hashAlgo
        swiSignature[ 'Signature' ] = signature

        swiSigStr = ''
        for key, value in swiSignature.items():
            swiSigStr += "%s:%s\n" % ( key, value )
        return swiSigStr

    def test_no_signature( self ):
        retCode = verify.verifySwi( self.test_swi )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_SIGNATURE_FILE )

    def test_not_a_zip_file( self ):
        testFile = self._writeFile( 'notaswi', 'stuff' )
        retCode = verify.verifySwi( testFile )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_NOT_A_SWI )

    def test_untrusted_signing_cert( self ):
        sig = self._makeSwiSignature( signingCert=BAD_SIGNING_CERT )
        self._addSigToSwi( sig )
        retCode = verify.verifySwi( self.test_swi, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_CERT_MISMATCH )

    def test_invalid_sig( self ):
        sig = self._makeSwiSignature()
        self._addSigToSwi( sig )
        retCode = verify.verifySwi( self.test_swi, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_VERIFICATION )

    def test_invalid_hash_algo( self ):
        sig = self._makeSwiSignature( hashAlgo='SHA-512' )
        self._addSigToSwi( sig )
        retCode = verify.verifySwi( self.test_swi, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_HASH_ALGORITHM )

    def test_malformed_signature( self ):
        self._addSigToSwi( 'bad sig' )
        retCode = verify.verifySwi( self.test_swi, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_SIGNATURE_FORMAT )

    def test_malformed_signature_key_value( self ):
        self._addSigToSwi( 'a:b\nc:d' )
        retCode = verify.verifySwi( self.test_swi, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_SIGNATURE_FORMAT )

    def test_malformed_signing_crt( self ):
        sig = self._makeSwiSignature( signingCert='bad cert' )
        self._addSigToSwi( sig )
        retCode = verify.verifySwi( self.test_swi, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_INVALID_SIGNING_CERT )

    def test_malformed_root_crt( self ):
        sig = self._makeSwiSignature()
        self._addSigToSwi( sig )
        rootCa = self._writeFile( 'root.crt', 'bad cert' )
        retCode = verify.verifySwi( self.test_swi, rootCA=rootCa )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_INVALID_ROOT_CERT )

    def test_use_arista_default_root_ca( self ):
        sig = self._makeSwiSignature()
        self._addSigToSwi( sig )
        retCode = verify.verifySwi( self.test_swi )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_CERT_MISMATCH ) 

if __name__ == '__main__':
    unittest.main()
