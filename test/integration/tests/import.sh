#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2017-2018, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

source helpers.sh

cleanup() {
    tpm2_evictcontrol -Q -a o -H 0x81010005 -p 0x81010005 2>/dev/null
    rm -f import_key.ctx  import_key.name  import_key.priv  import_key.pub \
          parent.ctx parent.pub  plain.dec.ssl  plain.enc  plain.txt  sym.key
          import_rsa_key.pub import_rsa_key.priv import_rsa_key.ctx import_rsa_key.name \
          private.pem public.pem priv.bin pub.bin plain.rsa.enc plain.rsa.dec

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shut-down"

tpm2_createprimary -Q -G 1 -g 0xb -a o -C parent.ctx
tpm2_evictcontrol -Q -a o -c parent.ctx -p 0x81010005

dd if=/dev/urandom of=sym.key bs=1 count=16 2>/dev/null

tpm2_readpublic -Q -H 0x81010005 --out-file parent.pub

#Symmetric Key Import Test
tpm2_import -Q -G aes -k sym.key -H 0x81010005 -f parent.pub -q import_key.pub \
-r import_key.priv

tpm2_load -Q -H 0x81010005 -u import_key.pub -r import_key.priv -n import_key.name \
-C import_key.ctx

echo "plaintext" > "plain.txt"

tpm2_encryptdecrypt -c import_key.ctx  -I plain.txt -o plain.enc

openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -p sym.key` -iv 0 \
-aes-128-cfb

diff plain.txt plain.dec.ssl
if [ $? != 0 ];then
echo "TEST: tpm2_import failed for Symmetric Key"
exit 1
fi

#Asymmetric Key Import Test
openssl genrsa -out private.pem 2048
openssl asn1parse -in private.pem -strparse 533 -out priv.bin -noout
openssl asn1parse -in private.pem -strparse 7 -out pub.bin -noout

tpm2_import -Q -G rsa -K pub.bin -k priv.bin -H 0x81010005 -f parent.pub \
-q import_rsa_key.pub -r import_rsa_key.priv

tpm2_load -Q -H 0x81010005 -u import_rsa_key.pub -r import_rsa_key.priv \
-n import_rsa_key.name -C import_rsa_key.ctx

openssl rsa -in private.pem -out public.pem -outform PEM -pubout
openssl rsautl -encrypt -inkey public.pem -pubin -in plain.txt -out plain.rsa.enc

tpm2_rsadecrypt -c import_rsa_key.ctx -I plain.rsa.enc -o plain.rsa.dec

diff plain.txt plain.rsa.dec
if [ $? != 0 ];then
echo "TEST: tpm2_import failed for Asymmetric Key"
exit 1
fi

exit 0
