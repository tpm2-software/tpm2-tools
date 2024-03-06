# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {

    rm -f \
    prim.ctx signing_key.ctx signing_key.pub signing_key.priv \
    att.data att.sig cp.hash rp.hash cphash.bin rphash.bin zero.bin

    if [ "${1}" != "no-shutdown" ]; then
        shut_down
    fi
}
trap cleanup EXIT

start_up

cleanup "no-shutdown"

#
# Get audit digest for a TPM command TPM2_GetRandom using and audit session
#
tpm2 clear

tpm2 createprimary -Q -C e -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 startauthsession -S session.ctx --audit-session

tpm2 getrandom 8 -S session.ctx --cphash cp.hash --rphash rp.hash

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 print -t TPMS_ATTEST att.data

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest for a TPM command TPM2_CC_Create in an audit session
#
tpm2 clear

tpm2 createprimary -Q -C e -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 startauthsession -S session.ctx --audit-session

tpm2 create -Q -C prim.ctx -u key.pub -r key.priv --cphash cp.hash \
--rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest for a TPM command TPM2_CC_Create in an audit session
#
tpm2 clear

tpm2 createprimary -Q -C e -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 createprimary -C o -c prim.ctx -G rsa
tpm2 readpublic -c prim.ctx -o prim.pub
tpm2 create -C prim.ctx -u key.pub -r key.priv -c key.ctx
tpm2 readpublic -c key.ctx -n key.name
echo "plaintext" > plain.txt
tpm2 makecredential -u prim.pub  -s plain.txt -n `xxd -p -c 34 key.name` \
-o cred.secret

tpm2 startauthsession -S session.ctx --audit-session

tpm2 activatecredential -c key.ctx -C prim.ctx -i cred.secret \
-o act_cred.secret -S session.ctx --cphash cp.hash --rphash rp.hash

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest for a TPM command TPM2_CC_Certify in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c primary.ctx

tpm2 create -Q -C primary.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 create -Q -g sha256 -G rsa -u certify.pub -r certify.priv -C primary.ctx

tpm2 load -Q -C primary.ctx -u certify.pub -r certify.priv -n certify.name \
-c certify.ctx

tpm2 startauthsession -S session.ctx --audit-session

tpm2 certify -Q -c primary.ctx -C certify.ctx -g sha256 -o attest.out -s sig.out \
--cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest for a TPM command TPM2_CC_CertifyCreation in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx \
-d create.dig -t create.ticket

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 create -G rsa -u rsa.pub -r rsa.priv -C prim.ctx -c certsigningkey.ctx

tpm2 startauthsession -S session.ctx --audit-session

tpm2 certifycreation -C certsigningkey.ctx -c prim.ctx -d create.dig \
-t create.ticket -g sha256 -f plain -s rsassa \
--cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_HierarchyChangeauth in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx \
-d create.dig -t create.ticket

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 startauthsession -S session.ctx --audit-session

tpm2 changeauth -c o ownerpassword --cphash cp.hash --rphash rp.hash \
-S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_ObjectChangeauth in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx \
-d create.dig -t create.ticket

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 create -Q -C prim.ctx -p foo -u key.pub -r key.priv -c key.ctx

tpm2 startauthsession -S session.ctx --audit-session

tpm2 changeauth -C prim.ctx -p foo -c key.ctx -r new.priv bar \
--cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_ChangeEPS in an audit session
#
tpm2 clear -Q

tpm2 startauthsession -S session.ctx --audit-session

tpm2 changeeps --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_ChangePPS in an audit session
#
tpm2 clear -Q

tpm2 startauthsession -S session.ctx --audit-session

tpm2 changepps --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_Define in an audit session
#
tpm2 clear -Q

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvdefine 0x1500016 -C o -s 32 -a "ownerread|ownerwrite" \
--cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_Extend in an audit session
#
tpm2 clear -Q

tpm2 nvdefine -C o -a "nt=extend|ownerread|policywrite|ownerwrite|writedefine" 1

tpm2 startauthsession -S session.ctx --audit-session

echo 'my data' | tpm2 nvextend -C o -i- 1 -S session.ctx \
--cphash cp.hash --rphash rp.hash

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )


#
# Get audit digest: TPM command TPM2_CC_Unseal in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

echo "plaintext" | \
tpm2 create -C prim.ctx -c key.ctx -u key.pub -r key.priv -i-

tpm2 startauthsession -S session.ctx --audit-session

tpm2 unseal -c key.ctx --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_nvsetbits in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

echo "plaintext" | \
tpm2 create -C prim.ctx -c key.ctx -u key.pub -r key.priv -i-

tpm2 nvdefine 1 -a "authwrite|ownerread|nt=bits"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvsetbits 1 -i 1 --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NVRead in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -a "authwrite|ownerread|ownerwrite" -s 32
echo "foo" | tpm2 nvwrite -i- 1 -C o

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvread 1 -C o -s 3 --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx
tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NVWrite in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -a "authwrite|ownerread|ownerwrite" -s 32

tpm2 startauthsession -S session.ctx --audit-session

echo "foo" | \
tpm2 nvwrite -i- 1 -C o --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_Certify in an audit session
#
tpm2 clear -Q

tpm2 createprimary -C o -c primary.ctx -Q

tpm2 create -G rsa -u signing_key.pub -r signing_key.priv -C primary.ctx \
-c signing_key.ctx -Q

tpm2 readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q

tpm2 nvdefine -s 32 -C o -a "ownerread|ownerwrite|authread|authwrite" 1

dd if=/dev/urandom bs=1 count=32 status=none| tpm2 nvwrite 1 -i-

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
-o signature.bin --attestation attestation.bin --size 32 1 -c o \
--cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_Increment in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -a "nt=counter|ownerread|authwrite"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvincrement 1 --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_WriteLock in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -C o -s 32 -a "authread|authwrite|writedefine"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvwritelock 1 -C 0x01000001 --cphash cp.hash --rphash rp.hash \
-S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_GlobalWriteLock in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -C o -s 32 -a "authread|authwrite|globallock"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvwritelock --global -C o --cphash cp.hash --rphash rp.hash \
-S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_ReadLock in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -C o -s 32 -a "authread|authwrite|read_stclear"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvreadlock 1 --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_Undefine in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -C o -s 32 -a "authread|authwrite|read_stclear"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvundefine 1 --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_UndefineSpaceSpecail in an
# audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 startauthsession -S special_session.ctx --policy-session
tpm2 policycommandcode -S special_session.ctx TPM2_CC_NV_UndefineSpaceSpecial \
-L policy.digest

tpm2 nvdefine 1 -C p -s 32 -a "authread|authwrite|policydelete|platformcreate" \
-L policy.digest

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvundefine 1 --cphash cp.hash --rphash rp.hash -S special_session.ctx \
-S session.ctx

tpm2 flushcontext special_session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# Get audit digest: TPM command TPM2_CC_NV_ReadLock in an audit session
#
tpm2 clear -Q

tpm2 createprimary -Q -C e -g sha256 -G rsa -c prim.ctx

tpm2 create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2 nvdefine 1 -C o -s 32 -a "authread|authwrite|read_stclear"

tpm2 startauthsession -S session.ctx --audit-session

tpm2 nvreadpublic 1 --cphash cp.hash --rphash rp.hash -S session.ctx

tpm2 getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx

tpm2 flushcontext session.ctx

dd if=/dev/zero bs=1 count=32 status=none of=zero.bin
dd if=cp.hash skip=2 bs=1 count=32 status=none of=cphash.bin
dd if=rp.hash skip=2 bs=1 count=32 status=none of=rphash.bin

diff \
<( cat zero.bin cphash.bin rphash.bin | openssl dgst -sha256 -binary ) \
<( tail -c 32 att.data )

#
# End
#
exit 0
