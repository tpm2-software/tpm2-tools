#!/bin/bash

source helpers.sh

TPM_CC_DUPLICATE=0x14B

cleanup() {
    rm -f primary.ctx new_parent.pub policy.dat session.dat key.prv key.pub \
          new_parent.ctx key.ctx duppriv.bin dupseed.bin

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

create_duplication_policy() {
    tpm2_startauthsession -Q -S session.dat
    tpm2_policycommandcode -Q -S session.dat -o policy.dat $TPM_CC_DUPLICATE
    tpm2_flushcontext -Q -S session.dat
    rm session.dat
}

start_duplication_session() {
    tpm2_startauthsession -Q -a -S session.dat
    tpm2_policycommandcode -Q -S session.dat -o policy.dat $TPM_CC_DUPLICATE
}

end_duplication_session() {
    tpm2_flushcontext -Q -S session.dat
    rm session.dat
}

echo -n -e  '\x01\x1a\x00\x01\x00\x0b\x00\x03\x00\x72\x00\x00'\
'\x00\x06\x00\x80\x00\x43\x00\x10\x08\x00\x00\x00'\
'\x00\x00\x01\x00\xd4\xa3\x5f\x93\xd6\x3a\x7d\x64'\
'\x64\x48\xcc\x36\x11\x6e\x4c\xd2\xd2\x6e\x6e\x6e'\
'\x34\x0a\xea\xeb\x1a\xbb\x77\xfb\x8a\xa3\x7a\x93'\
'\xcd\x4a\x02\xa6\x39\xef\x27\xb9\xfb\x1b\x27\x4a'\
'\x4f\xd9\x11\xa4\xd8\xa1\x01\x41\x11\xdf\x62\x0c'\
'\xa6\xd8\x56\xdc\xc5\x35\x70\x85\xa2\xb6\x72\xc9'\
'\x0f\xc0\xde\xb9\x74\x55\x95\x4c\x5d\x32\x9d\x9b'\
'\x64\x1c\xe6\xff\xce\xe4\x78\x34\xa9\x4e\x92\x6d'\
'\xcc\x86\xc4\x41\x6b\x32\x15\x51\xbf\x87\xcb\x07'\
'\xdf\xb9\xbd\xea\xa9\xaf\x54\xe5\x32\x2f\x99\x51'\
'\x94\xc7\x36\x24\x54\x5e\x66\xe8\x7a\x30\x1a\x0a'\
'\xdc\xb6\xa4\x9a\x26\x80\xd9\x1f\xfd\xf1\x60\xd2'\
'\x0f\x9a\x2e\xa1\x13\x25\x34\x36\x61\x2a\x5d\x79'\
'\x62\x55\xec\x6a\x63\x28\xd6\xcc\xc8\x87\x58\xcd'\
'\xd6\x05\xd8\x26\x2a\x9e\x6d\x48\xf3\x3e\x51\x68'\
'\xa2\x59\x4c\x41\xd4\x3f\xe7\x8c\xeb\xa1\xf7\xfe'\
'\x1e\x69\xf3\xb7\x05\x1c\x57\xc1\x34\xd2\x3c\xf9'\
'\x21\x98\x09\xe9\xcd\x2a\xb9\xc0\x43\x8e\x0d\x1d'\
'\xae\xe1\x81\xae\x45\x53\x4f\x4f\xc1\x8f\x2c\x26'\
'\x9b\x43\xeb\x1f\xfa\x0b\x28\x1e\x79\xbe\x88\x52'\
'\x04\xdd\x5b\xe5\x29\x65\xf7\x9d\xd5\xc0\x10\xd8'\
'\xd3\xed\x2a\x14\x21\x19\xc6\xa9' > new_parent.pub


tpm2_createprimary -Q -a o -g sha256 -G rsa -o primary.ctx
create_duplication_policy
tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub -L policy.dat -A "sensitivedataorigin|sign|decrypt"
tpm2_load -Q -C primary.ctx -r key.prv -u key.pub -o key.ctx

tpm2_loadexternal -Q -a o -u new_parent.pub -o new_parent.ctx

## Null Sym Alg
start_duplication_session
tpm2_duplicate -V -C new_parent.ctx -c key.ctx -G null -p "session:session.dat" -r dupprv.bin -S dupseed.dat
end_duplication_session

## AES Sym Alg, user supplied key
dd if=/dev/urandom of=sym_key_in.bin bs=1 count=16 status=none
start_duplication_session
tpm2_duplicate -V -C new_parent.ctx -c key.ctx -G aes -k sym_key_in.bin -p "session:session.dat" -r dupprv.bin -S dupseed.dat
end_duplication_session

## AES Sym Alg, no user supplied key
start_duplication_session
tpm2_duplicate -V -C new_parent.ctx -c key.ctx -G aes -K sym_key_out.bin -p "session:session.dat" -r dupprv.bin -S dupseed.dat
end_duplication_session

exit 0