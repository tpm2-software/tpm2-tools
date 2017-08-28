#;**********************************************************************;
#
# Copyright (c) 2016, Intel Corporation
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
#!/bin/sh

rm -f import_key.ctx  import_key.name  import_key.priv  import_key.pub
rm -f parent.ctx parent.pub  plain.dec.ssl  plain.enc  plain.txt  sym.key

tpm2_createprimary -G 1 -g 0xb -A o -C parent.ctx 
tpm2_evictcontrol -A o -c parent.ctx -S 0x81010005 

dd if=/dev/urandom of=sym.key bs=1 count=16

tpm2_readpublic -H 0x81010005 --opu parent.pub

tpm2_key_import -k sym.key -H 0x81010005 -f parent.pub -q import_key.pub \
-r import_key.priv

if [ $? != 0 ];then
	    echo "tpm2_key_import Failed"
		exit 1
fi
tpm2_load  -H 0x81010005 -u import_key.pub -r import_key.priv -n import_key.name \
-C import_key.ctx

echo "plaintext" > "plain.txt"
tpm2_encryptdecrypt -c import_key.ctx -D NO -I plain.txt -o plain.enc

openssl enc -in plain.enc -out plain.dec.ssl -d -K `xxd -p sym.key` -iv 0 \
-aes-128-cfb

diff plain.txt plain.dec.ssl
if [ $? != 0 ];then
	echo "tpm2_key_import test failed"
	exit 1
fi

tpm2_evictcontrol -A o -H 0x81010005 -S 0x81010005 
rm -f import_key.ctx  import_key.name  import_key.priv  import_key.pub
rm -f parent.ctx parent.pub  plain.dec.ssl  plain.enc  plain.txt  sym.key
