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
#!/bin/bash

echo "3a01000001000b00b20003002000837197674484b3f81a90cc8d46a5d724fd52\
d76e06520b64f2a1da1b331469aa000000000000000000000000000000000000\
0000000000000000000000000000000006008000430010000000000000080000\
000000000001c320e2f244a8601aacf3e01d26c665249935562de1da197e9e7f\
076c469613cfb653e98ec2c386fc1d133f2c8c6cc338b732f0b208bd838a877a\
3e5bbc3e1d4084e835c7c8906a1c05b4d2d30fdbebc1dbad950fa6b165bd4b6a\
864603146164c0c4f59d489011ef1f928deea6e90061f3d375e5646273151ef6\
22252098be1a4ab01dc0a12227c609fdaceb115af408d4693a6f49919774695b\
0c12bc18a1ff7120a7337b2fb5f1951d8bb7f094d5b554c11c9523b30729fe64\
787d0a13b9e630488dab4dfd86634a5270ec72fcc5a44dc679a8f32938dd8197\
e29dae839f5b4ca0f5de27c9522c23c54e1c2ce57859525118bd4470b18180ee\
f78ae4267bcd0000" | xxd -r -p > test_ek.pub

tpm2_getmanufec -g rsa -O -N -U -E ECcert.bin -f test_ek.pub -S https://ekop.intel.com/ekcertservice/
if [ $? != 0 ];then
 echo "tpm2_getmanufec command failed, please check the environment or parameters!"
 exit 1
fi

if [ $(md5sum ECcert.bin| awk '{ print $1 }') != "56af9eb8a271bbf7ac41b780acd91ff5" ]; then
 echo "Failed: retrieving endorsement certificate"
 exit 1
else
 echo "Successful: retrieving endorsement certificate"
fi

if [ ! -f ECcert.bin ]; then
 echo "ECcert.bin File not found!"
else
 rm -f ECcert.bin
fi
if [ ! -f test_ek.pub ]; then
 echo "ECcert.bin File not found!"
else
 rm -f test_ek.pub
fi 