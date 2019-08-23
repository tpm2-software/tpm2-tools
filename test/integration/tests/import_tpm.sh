# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
rm -f primary.ctx \
          new_parent.prv new_parent.pub new_parent.ctx \
          ipolicy.dat dpolicy.dat session.dat \
          key.prv key.pub key.ctx \
          dup.prv dup.pub dup.seed \
          key2.prv key2.pub key2.ctx \
          sym_key_in.bin \
          dup.ctx

    if [ "$1" != "no-shut-down" ]; then
          shut_down
    fi
}
trap cleanup EXIT

start_up

create_policy() {
    tpm2_startauthsession -Q -S session.dat
    tpm2_policycommandcode -Q -S session.dat -L $1 $2
    tpm2_flushcontext -Q session.dat
    rm session.dat
}

start_session() {
    tpm2_startauthsession -Q --policy-session -S session.dat
    tpm2_policycommandcode -Q -S session.dat -L $1 $2
}

end_session() {
    tpm2_flushcontext -Q session.dat
    rm session.dat
}

create_load_new_parent() {
    # Create new parent
    tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
    -u new_parent.pub -a "restricted|sensitivedataorigin|decrypt|userwithauth"
    # Load new parent key, only the public part
    tpm2_loadexternal -Q -C o -u new_parent.pub -c new_parent.ctx
}

load_new_parent() {
    # Load new parent key, public & private parts
    tpm2_load -Q -C primary.ctx -r new_parent.prv -u new_parent.pub \
    -c new_parent.ctx
}

create_load_duplicatee() {
    # Create the key we want to duplicate
    create_policy dpolicy.dat TPM2_CC_Duplicate
    tpm2_create -Q -C primary.ctx -g sha256 -G $1 -p foo -r key.prv -u key.pub \
    -L dpolicy.dat -a "sensitivedataorigin|decrypt|userwithauth"
    # Load the key
    tpm2_load -Q -C primary.ctx -r key.prv -u key.pub -c key.ctx
    # Extract the public part for import later
    tpm2_readpublic -Q -c key.ctx -o dup.pub
}

do_duplication() {
    start_session dpolicy.dat TPM2_CC_Duplicate
    if [ "$2" = "aes" ]
    then
        tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -G aes -o sym.key \
        -p "session:session.dat" -r dup.dup -s dup.seed
    else
        tpm2_duplicate -Q -C new_parent.ctx -c key.ctx -G null \
        -p "session:session.dat" -r dup.dup -s dup.seed
    fi
    end_session
}

do_import_load() {
    if [ "$2" = "aes" ]
    then
        tpm2_import -Q -C new_parent.ctx -k sym.key -u dup.pub -i dup.dup \
        -r dup.prv -s dup.seed -L dpolicy.dat
    else
        tpm2_import -Q -C new_parent.ctx -u dup.pub -i dup.dup -r dup.prv \
        -s dup.seed -L dpolicy.dat
    fi
    tpm2_load -Q -C new_parent.ctx -r dup.prv -u dup.pub -c dup.ctx
}

test() {
    # New parent ...
    create_load_new_parent
    # Key to be duplicated
    create_load_duplicatee $1
    # Duplicate the key
    do_duplication $2
    # Remove, we're done with it
    rm new_parent.ctx
    # Load the full thing this time
    load_new_parent
    # Import & load the duplicate
    do_import_load $2
}

# Part 1 : Duplicate 3 varieties of key (aes, rsa or ecc)
# and protect them using sym_alg null or aes, verify they
# can be imported & loaded
for dup_key_type in aes rsa ecc; do
    for sym_key_type in aes null; do
        tpm2_createprimary -Q -C o -g sha256 -G rsa -c primary.ctx
        test $dup_key_type $sym_key_type
        cleanup "no-shut-down"
    done
done

# Part 2 :
# Create a rsa key (Kd)
# Encrypt a message using Kd
# Duplicate Kd
# Import & Load Kd
# Decrypt the message and verify
tpm2_createprimary -Q -C o -g sha256 -G rsa -c primary.ctx
# New parent ...
create_load_new_parent
# Key to be duplicated
create_load_duplicatee rsa
# Encrypt a secret message
echo "Mary had a little lamb ..." > plain.txt
tpm2_rsaencrypt -Q -c key.ctx -o cipher.txt plain.txt
# Duplicate the key
do_duplication null
# Remove, we're done with it
rm new_parent.ctx
# Load the full thing this time
load_new_parent
# Import & load the duplicate
do_import_load null
# Decrypt the secret message using duplicated key
tpm2_rsadecrypt -Q -p foo -c dup.ctx -o recovered.txt cipher.txt
# Check we got it right ...
diff recovered.txt plain.txt
# Cleanup
rm plain.txt recovered.txt cipher.txt
cleanup "no-shut-down"

exit 0
