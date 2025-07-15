# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import base64
import pyparsing
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from switools import verify
from switools.verify import VERIFY_SWI_RESULT
from switools.create import create, validatorFuncs

from . import MockSigningServer

SIG_FILE_NAME = 'swix-signature'

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
        self.test_swix = self._testPath( 'Test.swix' )
        self.rpms = [ self._testPath( rpm ) for rpm in [ 'TestA.rpm' ] ]
        for rpm in self.rpms:
           self._writeFile( rpm, '' )
        create( self.test_swix, manifestYaml=None, rpms=self.rpms )

    def _testPath( self, filename ):
       return Path( self.test_dir, filename )

    def tearDown( self ):
        shutil.rmtree( self.test_dir )

    def _writeFile( self, filename, contents ):
        path = self._testPath( filename )
        with open( path, 'w' ) as f:
            f.write( contents )
        return path

    def _addSigToSwix( self, signature ):
        with zipfile.ZipFile( self.test_swix, 'a' ) as swix:
            swix.writestr( SIG_FILE_NAME, signature )

    def _makeSwixSignature( self, signingCert=MockSigningServer.MOCK_SIGNING_CERT,
                           signature=FAKE_SIGNATURE,
                           hashAlgo='SHA-256' ):
        swixSignature = {}
        swixSignature[ 'IssuerCert' ] = base64.standard_b64encode( signingCert.encode() ).decode()
        swixSignature[ 'HashAlgorithm' ] = hashAlgo
        swixSignature[ 'Signature' ] = signature

        swixSigStr = ''
        for key, value in swixSignature.items():
            swixSigStr += "%s:%s\n" % ( key, value )
        return swixSigStr

    def test_no_signature( self ):
        retCode = verify.verifySwi( self.test_swix )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_SIGNATURE_FILE )

    def test_not_a_zip_file( self ):
        testFile = self._writeFile( 'notaswix', 'stuff' )
        retCode = verify.verifySwi( testFile )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_NOT_A_SWI )

    def test_untrusted_signing_cert( self ):
        sig = self._makeSwixSignature( signingCert=BAD_SIGNING_CERT )
        self._addSigToSwix( sig )
        retCode = verify.verifySwi( self.test_swix, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_CERT_MISMATCH )

    def test_invalid_sig( self ):
        sig = self._makeSwixSignature()
        self._addSigToSwix( sig )
        retCode = verify.verifySwi( self.test_swix, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_VERIFICATION )

    def test_invalid_hash_algo( self ):
        sig = self._makeSwixSignature( hashAlgo='SHA-512' )
        self._addSigToSwix( sig )
        retCode = verify.verifySwi( self.test_swix, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_HASH_ALGORITHM )

    def test_malformed_signature( self ):
        self._addSigToSwix( 'bad sig' )
        retCode = verify.verifySwi( self.test_swix, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_SIGNATURE_FORMAT )

    def test_malformed_signature_key_value( self ):
        self._addSigToSwix( 'a:b\nc:d' )
        retCode = verify.verifySwi( self.test_swix, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_SIGNATURE_FORMAT )

    def test_malformed_signing_crt( self ):
        sig = self._makeSwixSignature( signingCert='bad cert' )
        self._addSigToSwix( sig )
        retCode = verify.verifySwi( self.test_swix, rootCA=self.root_crt )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_INVALID_SIGNING_CERT )

    def test_malformed_root_crt( self ):
        sig = self._makeSwixSignature()
        self._addSigToSwix( sig )
        rootCa = self._writeFile( 'root.crt', 'bad cert' )
        retCode = verify.verifySwi( self.test_swix, rootCA=rootCa )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_INVALID_ROOT_CERT )

    def test_use_arista_default_root_ca( self ):
        sig = self._makeSwixSignature()
        self._addSigToSwix( sig )
        retCode = verify.verifySwi( self.test_swix )
        self.assertEqual( retCode, VERIFY_SWI_RESULT.ERROR_CERT_MISMATCH )

class TestVersionStringValidator( unittest.TestCase ):
   def testGood( self ):
      manifestVersions = {
         1.0: (
            '4.22.3',
            '4.22.3*',
            '4.14.5FX*',
            '4.14.5.1*',
            '4.19*',
            '4.22.{3-12}',
            '4.{22-23}.1',
            '4.22.{3-$}',
            '4.{19-21}.{3-5}*',
            '4.22.{3-12}*',
            '4.22.3, 4.21.3*, 4.20.{3-12}*',
            '4.22.{3-$}*, 4.23.{2-3}*',
         ),
      }

      for mv in manifestVersions:
         validatorFunc = validatorFuncs[ mv ]
         versionStrings = manifestVersions[ mv ]
         for v in versionStrings:
            validatorFunc( [ v ] )

   def testBad( self ):
      manifestVersions = {
         1.0: (
            '',
            ' , ', # Only comma.
            ' , 4.22.3', # Comma prefix.
            '4.22.3,', # Trailing comma.
            'RTJ', # Not a version.
            '4.22.1+', # '+' is not a thing.
            '4.22.1; cat /etc/passwd', # Bobby Tables?
            '4..1', # '..' is not a thing.
            '4.{22-23.1', # Missing closing brace.
            '4.{2223}.1', # Not a range.
            '4.22.{1-3}F{4-7}', # Missing dot, letters aren't last.
            '}', # Just a curly brace.
            '4.22.1{1-3}3}', # Extra closing brace.
            '4.22.1{2}*', # Not a range.
            '4.22.1{{4-5}', # Extra open brace.
            '4.22.1{4--5}', # Extra dash in range.
            '4.22.1{2B-4}', # Bad lower bound for range.
            '4.22.1{1-9S}', # Bad upper bound for range.
            '4.22.1{4-2}', # Mixing number and range.
            '4.2{-5}.1', # Missing lower bound for range.
            '4.2{1-}.1', # Missing upper bound for range.
            '4.2{-}.5', # Missing bounds for range.
            '*', # Star used for major version.
            '4.2*.3*', # A fault in our stars.
         ),
      }
      for mv in manifestVersions:
         validatorFunc = validatorFuncs[ mv ]
         versionStrings = manifestVersions[ mv ]
         for v in versionStrings:
            with self.assertRaises( pyparsing.ParseException ):
               validatorFunc( [ v ] )

   def testUgly( self ):
      manifestVersions = {
         1.0: (
            ' 4  .   2  2 .3',
         ),
      }
      for mv in manifestVersions:
         validatorFunc = validatorFuncs[ mv ]
         versionStrings = manifestVersions[ mv ]
         for v in versionStrings:
            with self.assertRaises( pyparsing.ParseException ):
               validatorFunc( [ v ] )

if __name__ == '__main__':
    unittest.main()
