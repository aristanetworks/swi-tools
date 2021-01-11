# Copyright (c) 2018 Arista Networks, Inc.
# Use of this source code is governed by the Apache License 2.0
# that can be found in the LICENSE file.

import M2Crypto
import base64

MOCK_ROOT_CERT = """-----BEGIN CERTIFICATE-----
MIIFmzCCA4OgAwIBAgIJAKZwnaRNxPajMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRQwEgYDVQQHDAtTYW50YSBDbGFy
YTEYMBYGA1UECgwPQXJpc3RhIE5ldHdvcmtzMQ8wDQYDVQQDDAZhcmlzdGEwIBcN
MTgwNDEyMjIwMjI3WhgPMjI5MjAxMjUyMjAyMjdaMGMxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIDApDYWxpZm9ybmlhMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEYMBYGA1UE
CgwPQXJpc3RhIE5ldHdvcmtzMQ8wDQYDVQQDDAZhcmlzdGEwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDBD7SG0KsVyGiG5MR4daYPsaOAHJD76jehkHV0
ccyQOw3nY3DaHiYhHv/CslSJoEELMm8igcaKSvm0ZpYmq3KO4gDwcXMk8sczaN4n
eRp5LZRTH9CW5x66rZNhkOvNV63lomvYFX2QE6ZO9CczxlqdAXHNqdi/O+g1bjG4
EzKaHPODDS28+n3SbSrRW6MMycLCrX8iIKtQ57fmXrj3PVTkmj4HSQyQbqPeQMuK
cMmQdMQ0iJqKPgTJtx33MvCGbiLxB46k/Tocyzk0cXv+hRN2ewlUc6LlsMRfU+YU
ZL3f1G/sAGzAaF+hbKvYrC5o/R2P05g6KgRFHB7T/98vBAxVrL37m/tcdXHk99Uk
4/U8rTe7BsFHqTnT+h22sfn8ErRVuKSjj9+g82AQ1ttNd/CyCT5dSF4sp2xA7RoA
+L74mcm2tTgnE2c13oCB3cunKcos30YHQ0GpSa2At0VeDqNk95NWuL72NCaMCnx0
RpJHUxLQc3X1G1JmsZUNW7Dv23tWcowMue5bBfM6iwk+JLS9ua6WeWwwgOqyjJAo
HlpIjPjDrmJLowGrDnH2ZWSAacu7Hpo9ONzE3qjs2/YqMCjOurOBDP5zF7V8j295
Az4EKoXxav95YO40z3QYMwI82UpHvf9qBnLi8lANnZ309jrzcqlV5PBzeDQX7hYR
yvOx+QIDAQABo1AwTjAdBgNVHQ4EFgQUVSp8hdzDFSeG+nLQxodaL8nyW9cwHwYD
VR0jBBgwFoAUVSp8hdzDFSeG+nLQxodaL8nyW9cwDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAo9meUYtIrnxgkfQ/RXrEE5fdKJ1cowKtLUlK9UcxK+3W
OUSWmkAyLLMxt3ouQOqb9wjBpRMhcDx5Qh50rkidZjGRyOhCEU5u5mTGWe5ZMWyz
kzIFbdLLWOlYWjtarPXX/QLJcjEt42BVTmF0NjnBcgh4bruuiK1FQVqh+ag3bVuX
dcxXo76Bb1IIvW9+Fvbrlj882tNd0a7veKjS7F5s8h//fhljlJq3awH5cKF02ctH
4qGtIU1HL8hRF2J7aftIpP3z9YCO8FBdOjTgylMpIAf1YPYp+4AovTLwzU9hATis
7wep6Vr11nzZeVVetAn6NyQzuNsE8Mxdz8HplQgfeIbJfOb3Aj7x84V++HE2FlyC
Z5h+AfbCUQUSBAI34KU8o0/1TWk/H+pUzMH4w8djI7KIm5lC16re3UHkdQZe6FRa
5I+fnXd4UEbCtMJqPoZ+x8foECTzx3e8wQtPu9xEEef5ZljRhzbM1pUImHa8tfk3
pUtqYsNsthkEe99ggoLaJdaOnFF3hZYAne1vhIuxT+XlTRd33pZQ7Knxb+HZvR8/
2xpAXlmxlG6SDCb84AwJ+XJ/MWnCzP/PlV2CJuymwkXCv+4hJd3qmif1BvOzRt4x
IOl7uzluBu5MA/oDliIE2O0e6UZCAz43IqH3SjgNwxb78mv6fmtRnLUiY6yhA3w=
-----END CERTIFICATE-----"""

MOCK_SIGNING_CERT = """-----BEGIN CERTIFICATE-----
MIIFPDCCAyQCAQEwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxEzARBgNV
BAgMCkNhbGlmb3JuaWExFDASBgNVBAcMC1NhbnRhIENsYXJhMRgwFgYDVQQKDA9B
cmlzdGEgTmV0d29ya3MxDzANBgNVBAMMBmFyaXN0YTAgFw0xODA3MjUyMDQ1NDFa
GA8yMjE4MDYwNzIwNDU0MVowYzELMAkGA1UEBhMCQ0ExEzARBgNVBAgMCkNhbGlm
b3JuaWExFDASBgNVBAcMC1NhbnRhIENsYXJhMRgwFgYDVQQKDA9BcmlzdGEgTmV0
d29ya3MxDzANBgNVBAMMBmFyaXN0YTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAO/MX6Ckgf4Ayb9aeNhIL/Ou9fWYrkzahhOWWLTHAmu0NDgwfxlfsAmK
78wVrICc2/kvDBx126i2ssbPUKlQEtR5metaTVp4qhDhmTDvYd5VWv9xarBvZ12G
uhApFejDF27y7+ZSOKvudeQxVASWOvEzZZllrv6n0X22r91F2kOc5fIA5D/z67pi
8iahX+imCdHLv82/FzTz+FzJ0AoQ1p0p9bWNWhbeqN/fyufPlQPOek9f7HAtjJ0t
p4Yfl2VIHYwQ/cA9cdWzmkm0UPdqTZiTu53wBQGrLwE3bFRwBdo+XlPytle/NgYb
EDpDF4Rdv2NKeovIXiDJwjvKbsxeHBnupARSLU4H9nwKbLJJ2mjgJbjRj+JVnmlH
PxpfeE9q6qU5Ta6mSkqSHob0/jqH0K0jcYMhrX/PwEQtLEUpcJogN8jtXltzuG9m
ZYVQcuv1WNFhXy5s9wGAfBOkDMvJYoTRpPFx/bYQds/JaJm8eC0C3BWWZbUOS9Xl
YElmrF+FElYp9LhsJ/M5sGhK4bhQAXE8+dM6M3ZF0RQ/dWPsxVcqDyz7ExZgrYgS
UoHZzt5Y88AWZRvWhGJOU4QdheA1Cx+EmgiU+oK8XWKmWvMusqcc3Hdv3JhXKIK3
O034ZJhx0htzEG07Rj6Qaa9O5oRFkcYTSk+URh2APM6IzU+lcnjHAgMBAAEwDQYJ
KoZIhvcNAQELBQADggIBAF5Km4BD/De9uHSv9mQfBXp+2AD7yhhSyjQnuwM7a94m
Y4TRV1lIT5eqZBgIiPyjXau3y0DLvfj1juJP3Lrev3gSgFdWih3XmduHDSqx4zsQ
x+ZeUuptoRcQmQ+wImfd6k/olhrmnhEAhZeRDT/nNvqMid6U5OS+dYiBeoGMeR/a
02aaHakjxMDJANZJkkQ8kmD4qIhZvICEI1CxTQHGVaAKc9rHWPoY7Bh88D2BQOzh
GCiSXJ8xvSVLFRXkf9jYXSus1VpcZ+iMEmMliHQ9ON0nGJsMBdvnbfTzZexl7rMw
k1Z7LSgUmQRIcSO5G1q9HrT60AWlrz/bvnfsQ/S1JX4OG6SCfvDBfmdlDyJpJVuK
9KbW06cKhWpvG1SapslEKaF0XyYnCLt+bjoskSvy7e9SZq717yB0S8tjn+GVAPU4
IpKJMZ80RNNZM68I5NAGbzDjoTdtiTAt+ymTN2OpTshMrFQcMVju/l+OkdQQCc+u
HYPskNJeOU3Yt4Tj/C2b/wF6PoM5gIjr2nEI6KVBO4qNF11pEJ16gD6UzUU4QJ0G
ZA0sw7ClR7PUgf3AD9+8FCxPCC/ILX5xdmfHGXJbB0PB2O//zt72nP5WRsyCODem
2VoxfFLNrC5bxeA/T0+NjiBY0qfSbz6TDT6JpOqGO3CH3oRQYZRHYh3lj4VZOkHm
-----END CERTIFICATE-----"""

MOCK_SIGNING_KEY = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

def getTestSignature( swiFile ):
    with open( swiFile, 'rb' ) as swi:
        key = M2Crypto.EVP.load_key_string( MOCK_SIGNING_KEY.encode() )
        key.reset_context( md='sha256' )
        key.sign_init()
        key.sign_update( swi.read() )
        return base64.b64encode( key.sign_final() ).decode()
