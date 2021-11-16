#!/usr/bin/env python3.7
import os
import sys
from base64 import b64encode

# Just a simple implementation of a signing service for testing purposes.
# This signing service does not contact any signing server, it just uses a local 
# signing key and uses that to sign the given sha256. Eos signatures are over the
# sha256sum of the image with a 4k key size, we just handle that case.
# The swi-signature script does the sha256 on the image and passes it to this script
# (if the given options don't provide a signer's key, otherwise no need to call this
# script). The swi-signature also passes the filename were the resulting signature
# should be placed in.
# This script assumes the signer's key to be in /etc/swi-signing-devCA/signing.key
# (and does not bother to verify if it exists, this is just test code).

def main():

   if len( sys.argv ) != 3:
      print( "Error" )
      print( "usage: %s <sha256-string> <file-to-hold-signed-sha256-string>" % sys.argv[0] )
      sys.exit( -1 )
   
   digest = sys.argv[1]
   resultFile = sys.argv[2]
   
   padSha256k4096="0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"
   sha256Magic = "3031300d060960864801650304020105000420"
   
   # Generate signature from sha256 hash and private key
   # pad the hash to the key length, and encode the hashing method into it as per RSAES-PKCS1-V1_5
   # find the modulo and exponent from the private key
   # compute the signature using modulo and exponent
   # convert it to base64 encoding
   
   digest = int( "%s%s%s" % ( padSha256k4096, sha256Magic, digest ), 16 )
   workDir = "/tmp/swi-signing-server-%d" % os.getpid()
   os.system( "mkdir %s" % workDir )
   os.system( "openssl rsa -in /etc/swi-signing-devCA/signing.key -text -noout | sed -n '/modulus:/,/^[^ ]/p' | sed '1d' | sed '$d' | sed 's/ //g' | sed 's/://g' | tr -d '\n' > %s/m" % workDir )
   os.system( "openssl rsa -in /etc/swi-signing-devCA/signing.key -text -noout | sed -n '/privateExponent:/,/^[^ ]/p' | sed '1d' | sed '$d' | sed 's/ //g' | sed 's/://g' | tr -d '\n' > %s/e" % workDir )
   m = int( open( "%s/m" % workDir).read(), 16 ) # not bothering to close()...
   e = int( open( "%s/e" % workDir).read(), 16 )
   os.system( "rm -rf %s" % workDir )
   signature = pow( digest, e, m )
   signature_bytes = signature.to_bytes( 512, byteorder='big', signed=False )
   b64_signature = b64encode( signature_bytes )
   with open( resultFile, 'wb+') as file:
      file.write( b64_signature )
   
   # For comparison, double check with openssl: Generate the signature from the file to sign and the private key
   # openssl dgst -sha256 -sign /etc/swi-signing-devCA/signing.key -out /tmp/digest /the/file/to/sign;
   # hexdump /tmp/digest | head -n 2
   # hexdump /tmp/digest | tail -n 2

if __name__ == '__main__':
   main()
