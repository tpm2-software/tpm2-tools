#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause

echo 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' | base64 -d > header.bin
echo '02 03' | xxd -r -p >mid-header.bin
echo '01 00 01' | xxd -r -p >exponent.bin
dd if=$1 of=modulus.bin bs=1 count=256 skip=102
cat header.bin modulus.bin mid-header.bin exponent.bin > $1.cer
openssl rsa -in $1.cer -inform DER -pubin > $1.pem
rm header.bin modulus.bin mid-header.bin exponent.bin
