# swi-tools
Scripts for operating on an Arista SWI or SWIX

A SWI is a SoftWare Image containing the software that will run on the switch when the image is booted.
A SWIX is a SoftWare Image eXtension, a collection of files (ex RPMs, squashfs) that can be installed to extend the behavior of the base SWI.

## Scripts
* **swi-signature**: Add a cryptographic signature to an Arista SWI or SWIX
* **swix-signature**: A convenience alias for the above
* **verify-swi**: Verify the cryptographic signature of an Arista SWI or SWIX
* **verify-swix**: A convenience alias for the above
* **swix-create**: Create a new SWIX file
* **swi-signing-service**: Simple example of a signing service (all local)

## Installation
```
pip3 install switools
```
Alternatively:
```
git clone https://github.com/aristanetworks/swi-tools.git
cd swi-tools
python3 setup.py install
```
### Dependencies
0. Python3. For a version that works with python2, use the version 1.0 release.
1. [Zip](http://infozip.sourceforge.net/) - Used in the `swi-signature` script to remove a signature from the SWI/X if you want to re-sign it, this comes preinstalled on many operating systems.
2. [M2Crypto](https://pypi.org/project/M2Crypto/) - installed automatically with the setup script.
3. [PyYAML](https://pyyaml.org) - Used to read the manifest.yaml, if added, when creating a SWIX.
4. [jsonschema](http://json-schema.org) - Used to verify the manifest.yaml, if added, when creating a SWIX.

## Creating a SWIX
Creating a SWIX is a straightforward process involving the `swix-create` command.
```
$ swix-create -h
usage: swix-create [-h] [-f] [-i manifest.yaml]
                   OUTFILE.swix PACKAGE.rpm [PACKAGE.rpm ...]

positional arguments:
  OUTFILE.swix          Name of output file
  PACKAGE.rpm           An RPM to add to the SWIX

optional arguments:
  -h, --help            show this help message and exit
  -f, --force           Overwrite OUTFILE.swix if it already exists
  -i manifest.yaml, --info manifest.yaml
                        Location of manifest.yaml file to add metadata to SWIX
```
### 1. Creating a simple SWIX
```
$ swix-create MySwix.swix MyRpm.rpm
  adding: manifest.txt (stored 0%)
  adding: MyRpm.rpm (stored 0%)
```
Your SWIX is ready to be installed on a switch!
```
(Arista)# scp user@host:/path/MySwix.swix extension:
Copy completed successfully.
(Arista)# show extensions
Name             Version/Release      Status      Extension
---------------- -------------------- ----------- ---------
MySwix.swix      1.0.3/1.el7          A, NI       1
(Arista)# extension MySwix.swix
Note: no agents to restart
```
Et voilà! Your extension has been installed. Note that your extension may require some agents to be restarted. e.g., A restart of ConfigAgent is required if any CLI plugins have been added.
### 2. Adding a manifest.yaml file
The functionality of the SWIX can be enriched by adding a YAML file which contains instructions on when and how to install certain files. Such file is added with the `-i` switch, followed by the file, which will get validated and added to the SWIX. A sample manifest.yaml
```
metadataVersion: 1.0
version:
  - 4.21.1*:
    - AppBeta.rpm
    - AppBeta-lib.rpm
    - AppBeta.squashfs:
      - mount: /opt/apps/hello_world
  - 4.20.{6-9}*:
    - AppStable.rpm
    - AppStable.squashfs:
      - mount: /opt/apps/hello_world
agentsToRestart:
  - ConfigAgent
  - IgmpSnoopingAgent
```
At the moment, the only supported metadata version is `1.0`. The other entry is the version-specific instructions for the extension. The first indented entry reads as:
* For EOS versions 4.25.1 (Also 4.25.1.1, 4.25.1FX, etc., but not 4.25.10)
  * Install `AppBeta.rpm`
  * Install `AppBeta-lib.rpm`
  * Mount the SquashFS file `AppBeta.squashfs` on `/opt/apps/hello_world`
  * Prompt the user that `ConfigAgent` and `IgmpSnoopingAgent` need to be restarted. This only works on EOS versions 4.25.1 and later.

This way, you can publish one SWIX that works on multiple versions of EOS.
## Signing an Arista SWI/X
Signing an Arista SWI or SWIX is a multi-step process involving the `swi-signature` script. First, with `swi-signature prepare`,
a null signature file (a fix-sized signature file made entirely of null bytes) is added to the SWI/X, at the path `/swi-signature` (for SWI files) or `/swix-signature` (for SWIX files) in the zip file. 
Next, a signature is generated from the resulting SWI/X using a signing key. Finally, with `swi-signature sign`, the null signature file in the SWI/X is 
updated to reflect both the signature that was generated and the signing certificate used to verify the signature.

For EOS images starting 4.27.2, the process changes a little. For that, version 1.2 of this tool is needed.
That is because a 4.27.2 image will contain multiple images, thus the prepare/sign split becomes inpractical. Instead, one has to provide a "swi-signing-server" binary (somewhere in PATH) that given a digest will return it signed. In that case, the swi-signing-server has access to the signer's private key. There is an example of how such a swi-signing-server could look like (it is using a local key). So in case no signer key is provided on the command line, providing a signatureFile instead will no longer do (it will still work though if the image is a pre 4.27.2 image).
With 4.27.2+ images, the null-signature is automaticaly added and will overwrite any pre-existing signature forcefully.

### 1. Preparing the SWI/X for signing
Before generating a signature of the SWI/X, the SWI/X must be pre-signed with a null signature, a fix-sized signature file made entirely of null bytes. 
This can be done with the `prepare` option in the `swi-signature` script. At the end of the preparation, the sha256 hash of the SWI/X with the null signature 
is printed out in hex format. The hash is used in the next step to generate the real signature of the SWI/X file.
```
$ swi-signature prepare -h
usage: swi-signature prepare [-h] [--force-sign] [--outfile OUTFILE]
                             [--size SIZE]
                             EOS.swi[x]

positional arguments:
  EOS.swi[x]         Path of the SWI/X to prepare for signing

optional arguments:
  -h, --help         show this help message and exit
  --force-sign       Force signing the SWI/X if it's already signed
  --outfile OUTFILE  Path to save SWI/X with null signature, if not replacing
                     the input SWI/X
  --size SIZE        Size of null signature to add (default 8192 bytes)
```
Examples:
```
$ swi-signature prepare EOS.swi
84f6e823976f6d499fb161c2502ba9474b68abca7e98a9c98251ea5bd5e93765
```
This adds a null signature of 8192 bytes (the default) to EOS.swi, and prints out its sha256 hash in hex format. Keep track of this hash 
for use in the next step, as input into a signing server to generate a signature signed by a private key.

```
$ swi-signature prepare EOS.swi --force-sign --outfile EOS_temp.swi --size 9000
deleting: swi-signature
10aa98f4bd283256c8cd922d1bf40fb1b25a13d97049e4c0135e7140cb63d579
```
This copies EOS.swi to EOS_temp.swi, and signs EOS_temp.swi with a null signature of 
9000 bytes, even if it has been signed before (removes the old signature).

Signing SWIX files behaves the same.

### 2. Signing the SWI/X
After adding a null signature file to the SWI/X, the SWI/X can now be signed. The null signature will be replaced by a real signature
that contains both the signature of the SWI/X and the signing certificate that will be used to verify the signature. There are two options depending on whether 
you have direct access to the signing private key.
```
$ swi-signature sign -h
usage: swi-signature sign [-h]
                          (--signature SIGNATURE.txt | --key SIGNINGKEY.key)
                          EOS.swi[x] SIGNINGCERT.crt ROOTCERT.crt

positional arguments:
  EOS.swi[x]            Path of the SWI/X to sign.
  SIGNINGCERT.crt       Path of signing certificate.
  ROOTCERT.crt          Root certificate of signing certificate to verify
                        against 

optional arguments:
  -h, --help            show this help message and exit
  --signature SIGNATURE.txt
                        Path of base64-encoded SHA-256 signature file of EOS.swi or swix, signed by
                        signing cerificate.
  --key SIGNINGKEY.key  Path of signing key, used to generate the signature
```

#### 2a. Signing SWI/X without direct access to private key
If there is no direct access to the private key, we assume that the private key is stored remotely in some form of signing server. A user should be able to 
query this signing server to use the signing key to sign an input hash and return the resulting signature.
The input hash that should be used is printed out in the `swi-signature prepare` step. Since it is given in hex format, the signing server 
should be able to accept this sha256 hash in hex format as an input. The signing server should then sign the input hash with its signing private key, and then 
return the resulting signature as well as the signing certificate corresponding to the private key. The resulting signature must be converted to base64 
format to be used in the `swi-signature sign` script.

Example:
```
$ # Prepare EOS.swi for signing and save the hash to input_hash.txt
$ swi-signature prepare EOS.swi > input_hash.txt                    
 
$ # input_hash.txt is a sha256 hash of EOS.swi in hex format
$ cat input_hash.txt
0f1f680a7c97f274cf2b6d131595521fec2a97509aceaddac529b7ab46ef6f8f

$ # Invoke a script that talks to a signing server that takes a hash as input and returns the signing certificate and generated signature.
$ ./talk-to-signing-server --input input_hash.txt --outputCertFile signing.crt --outputSignatureFile signature.txt 

$ # The resulting signature must be in base64 format
$ cat signature.txt
MEYCIQCcpjTgTZm9c+QdlVJ0W6xe7sxhjs7KXbwDngwC3/66QwIhAL7SRpkPOtOSyJPDlEqhyLzziQyght/E1iUSpmvEXmxg
$
$ swi-signature sign EOS.swi signing.crt root.crt --signature signature.txt
SWI file EOS.swi successfully signed and verified.

```
Signs EOS.swi with a pre-generated signature. At the end of signing, the resulting SWI will be automatically verified with the user-provided root certificate. SWIX signing behaves the same.

#### 2b. Signing SWI/X with direct access to private key
If there is direct access to the private key, the key can be used directly in the input to the signing script as follows:
Examples:
```
$ swi-signature sign EOS.swi signing.crt root.crt --key signing.key
SWI file EOS.swi successfully signed and verified.
```
Signs EOS.swi using `signing.crt`. The signature used is created by signing the hash of EOS.swi with `signing.key`.

#### 2c. Signing EOS 4.27.2+ SWI with direct access to private key
Example:
```
$ swi-signature sign EOS.swi /etc/swi-signing/signing.crt /etc/swi-signing/root.crt --key /etc/swi-signing/signing.key
Optimizations in EOS.swi: Default Sand-4GB Strata-4GB
Default sha256: a3276b9976bb2471838dc95fbd2a38dcf1e7e5510bcfa8dfe0f0eff8b935a709
Sand-4GB sha256: 4d0d23293eaecc7f55e7ee9776b0c250bef1a335e1b4ea28ef4eea989eb917f9
Strata-4GB sha256: 520cbde6d60d1089bfbc95d9086c47ce4a6fc0399a5b8a29fc6c1bd95c7d029a
Adding signature files to EOS.swi: Default.signature Sand-4GB.signature Strata-4GB.signature
EOS.swi sha256: 913eb842e408ceddea914543230c9e13ff63e360fc6a6735ef9c0c1571209fb3
SWI/X file EOS.swi successfully signed and verified.
```
#### 2d. Signing EOS 4.27.2+ SWI without direct access to private key
Example:
```
$ which swi-signing-service
/usr/local/bin/swi-signing-service

$ swi-signature sign EOS.swi /etc/swi-signing/signing.crt /etc/swi-signing/root.crt
... (same as above)
```

## Verifying an Arista SWI/X signature
The `verify-swi` script verifies the signature in a SWI or SWIX by checking that the signing certificate
used to sign the SWI/X is trusted by a specified root certificate, and that signing the SWI/X with the signing certificate matches
the signature of the SWI/X. By default, the script verifies the signing certificate against the Arista root certificate, which is installed 
with the package.
```
$ verify-swi -h
usage: verify-swi [-h] [--CAfile CAFILE] EOS.swi[x]

Verify Arista SWI image or SWIX extension

positional arguments:
  EOS.swi[x]       SWI/X file to verify

optional arguments:
  -h, --help       show this help message and exit
  --CAfile CAFILE  Root certificate to verify against. (default:
                   ARISTA_ROOT_CA.crt)
```
Examples:
```
$ verify-swi EOS.swi 
SWI verification failed.
$ echo $?
4
```
The above example verifies EOS.swi using the Arista root certificate.
However, the signature is not valid. Invalid signature verification returns a non-zero return code.

```
$ verify-swi EOS.swi --CAfile root.crt
SWI verification successful.
$ echo $?
0
```
Here EOS.swi is verified using `root.crt`. Verification in this case was successful.
```
$ verify-swi EOS.swi --CAfile /etc/swi-signing/root.crt
Optimizations in EOS.swi: Default Sand-4GB Strata-4GB
Default: SWI/X verification successful.
Sand-4GB: SWI/X verification successful.
Strata-4GB: SWI/X verification successful.
SWI/X verification successful.
```
Above's output was for a 4.27.2+ image (which has multiple contained images)

## Testing
To run unit tests:
``` 
python3 setup.py test 
```
End-to-end tests after install:
``` 
./tests/swim_test.sh 
```
