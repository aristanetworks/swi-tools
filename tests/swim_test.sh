#!/bin/bash

# tmp files will be relative to test file
dir=$(dirname ${0})
cd $dir
mkdir -p tmp
# Redirect output to a log file to compare to reference output later.
logFile=$(basename ${0%.*}.log)
logRef=$(basename ${0%.*}.ref)
echo "Test output is redirected to '$dir/$logFile', and later compared to reference '$dir/$logRef'"
exec 3>&1 # save stdout to fd 3
exec 1<> $logFile # open stdout to log file

# Create key pairs and certs for usage in the test:
#   certs/root.key     root CA that will sign the signer's cert
#   certs/root.cert
#   certs/signer.key   the signer of the image, entrusted by the root CA
#   certs/signer.cert
if [ ! -d certs ]; then
   mkdir certs
   cd certs
   cat > root_config_file <<EOF
   [req]
   distinguished_name=dn
   [ dn ]
   [ ext ]
   basicConstraints=CA:TRUE,pathlen:0
   extendedKeyUsage = serverAuth, clientAuth, codeSigning
   keyUsage = keyCertSign
EOF
   
   cat > child_config_file <<EOF
   [req]
   distinguished_name=dn
   [ dn ]
   [ ext ]
   extendedKeyUsage = serverAuth, clientAuth, codeSigning
EOF
   
   # generate key/cert for root CA
   openssl req -new -newkey rsa:4096 -nodes -x509 -days 100 \
      -config root_config_file -extensions ext \
      -subj "/CN=rootCA" \
      -keyout root.key \
      -out root.cert
   
   # generate key/csr for user 'signer'
   openssl req -new -newkey rsa:4096 -nodes \
      -subj "/CN=signer" \
      -out signer.csr \
      -keyout signer.key
   
   # generate cert for user 'signer' (have root CA sign the csr)
   openssl x509 -req -sha256 -days 100 \
      -extensions ext -extfile child_config_file \
      -in signer.csr \
      -CA root.cert -CAkey root.key \
      -set_serial 123 \
      -out signer.cert
   cd ..
fi

# keep original images orignal
cp EOS.swi.1.0 tmp/EOS.swi
cp EOS.swi.3.0 tmp/EOS.swim
limage=tmp/EOS.swi # legacy formatted image
mimage=tmp/EOS.swim # modular image

signerCert="certs/signer.cert"
rootCert="certs/root.cert"
signerKey="certs/signer.key"
signerKeyPath=$(readlink -f $signerKey)

#signerCert="/etc/swi-signing-devCA/signing.crt"
#rootCert="/etc/swi-signing-devCA/root.crt"
#signerKey="/etc/swi-signing-devCA/signing.key"
#signerKeyPath=$(readlink -f $signerKey)

function run() {
  echo "> $1"
  eval $1 2> tmp/e > tmp/out
  ret=$?
  cat tmp/out | sed 's/sha256: [a-f0-9]*/sha256: xxx/'
  echo "retCode: $ret"
  echo "stderr: $(cat tmp/e)"
}

function srun() { # silent run
  echo "> $1"
  eval $1 
}

# -------------- Start of tests --------------------------------------------

echo
echo "# Without Signing-Service (with key on command line)"
echo "# ======================="
run "swi-signature sign $mimage $signerCert $rootCert --key $signerKey"
run "verify-swi $mimage --CAfile $rootCert"

echo
echo "# With Signing-Service"
echo "# ===================="
run "SWI_SIGNING_KEY=$signerKeyPath swi-signature sign $mimage $signerCert $rootCert"
run "verify-swi $mimage --CAfile $rootCert"

echo
echo "# Legacy image, one step (with key or with new singing-service)"
echo "# ======================"
run "swi-signature sign $limage $signerCert $rootCert --key $signerKey"
run "verify-swi $limage --CAfile $rootCert"
run "SWI_SIGNING_KEY=$signerKeyPath swi-signature sign $limage $signerCert $rootCert"
run "verify-swi $limage --CAfile $rootCert"

echo
echo "# Legacy image, two steps"
echo "# ======================="
sha256=$(swi-signature prepare $limage --force-sign)
signatureFile=/tmp/test-signed-sha256
SWI_SIGNING_KEY=$signerKeyPath swi-signing-service $sha256 $signatureFile 2>e; echo $?
run "swi-signature sign $limage $signerCert $rootCert --signature=$signatureFile"
run "verify-swi $limage --CAfile $rootCert"

echo
echo "# Check signature is not successful my chance"
echo "# ==========================================="
echo "# Touching the signature will invalidate the signature"
srun "unzip -oq $mimage swi-signature"
srun "cp --preserve=timestamps swi-signature swi-signature.orig"
srun "touch swi-signature"  # timestamp change will fail signature
srun "zip -0 -X -q $mimage swi-signature"
run "verify-swi $mimage --CAfile $rootCert"
echo ""
echo "# Corrupt the certificate (and restore the timestamp)"
srun "sed -i 's/IssuerCert:.../IssuerCert:xxx/' swi-signature"
srun "touch -r swi-signature.orig swi-signature # restore timestamp"
srun "zip -0 -X -q $mimage swi-signature"
run "verify-swi $mimage --CAfile $rootCert"
echo ""
echo "# restore the certificate, add an inner image error"
srun "cp --preserve=timestamps swi-signature.orig swi-signature"
srun "unzip -oq $mimage Sand-4GB.signature"
srun "cp --preserve=timestamps Sand-4GB.signature Sand-4GB.signature.orig"
srun "touch Sand-4GB.signature"
srun "sed -i 's/IssuerCert:.../IssuerCert:xxx/' Sand-4GB.signature"
srun "zip -0 -X -q $mimage swi-signature Sand-4GB.signature"
run "verify-swi $mimage --CAfile $rootCert"
echo ""
echo "# Double check: fix up things, should work again."
srun "cp --preserve=timestamps swi-signature.orig swi-signature"
srun "cp --preserve=timestamps Sand-4GB.signature.orig Sand-4GB.signature"
srun "zip -0 -X -q $mimage swi-signature Sand-4GB.signature"
run "verify-swi $mimage --CAfile $rootCert"
echo ""
echo "# delete an inner signature"
srun "zip -d $mimage Sand-4GB.signature"
run "verify-swi $mimage --CAfile $rootCert"
echo ""
echo "# delete outer signature file"
srun "zip -d $mimage swi-signature"
run "verify-swi $mimage --CAfile $rootCert"
echo ""
echo ""
echo "# restore all"
cp EOS.swi.1.0 $limage
cp EOS.swi.3.0 $mimage
#srun "cp --preserve=timestamps swi-signature.orig swi-signature"
#srun "cp --preserve=timestamps Sand-4GB.signature.orig Sand-4GB.signature"
#srun "zip -0 -X -q $mimage swi-signature Sand-4GB.signature"
#run "verify-swi $mimage --CAfile $rootCert"

echo
echo "# Error cases"
echo "# ==========="
echo "# bad image name"
run "swi-signature sign what-image.swi $signerCert $rootCert"

echo
echo "# bad image file"
touch tmp/junk
zip tmp/some.zip tmp/junk >& /dev/null
run "swi-signature sign tmp/some.zip $signerCert $rootCert"

echo
echo "# already signed image"
run "swi-signature prepare $limage"

echo
echo "# invalid signature"
sha256="e8d6bb8252feb4d916352a35567dd11350996257f854480cbad0c38374962c17"
swi-signing-service $sha256 $signatureFile
run "swi-signature sign $limage $signerCert $rootCert --signature=$signatureFile"
run "verify-swi $limage --CAfile $rootCert"

echo
echo "# error in signing service, no key found"
run "SWI_SIGNING_KEY=doesNotExist swi-signature sign $limage $signerCert $rootCert"
echo "Tests finished"

exec 1>&3 # restore orignal stdout
exec 3<&- # close the copy
# report results
diff -up $logRef $logFile && echo "Test PASSED" || { echo "Test FAILED"; exit -1; }

