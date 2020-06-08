# SPDX-License-Identifier: BSD-3-Clause
#;**********************************************************************;

source helpers.sh

source_parent_object=src_o.ctx
new_parent_object=dst_n.ctx
new_parent_name=dst_n.name
duplicable_object_private=dupkey.priv
duplicable_object_public=dupkey.pub
duplicable_object=dupkey.ctx
duplicable_object_name=dupkey.name
policy_duplication_select=policydupselect.dat
duplicated_object_private=dupkey_new.priv
duplicated_object_seed=dupseed.dat
policy_session=session.dat
unintended_new_parent_object=dst2_n.ctx
unintended_new_parent_name=dst2_n.name


cleanup() {
  rm -f $source_parent_object $new_parent_object $new_parent_name \
  $duplicable_object_private $duplicable_object_public $duplicable_object \
  $policy_duplication_select $duplicated_object_private $policy_session \
  $duplicated_object_seed $duplicable_object_name \
  $unintended_new_parent_object $unintended_new_parent_name \

  if [ "$1" != "no-shut-down" ]; then
     shut_down
  fi
}

trap cleanup EXIT

start_up

cleanup "no-shut-down"

# Error trapped and reported
tpm2 clear

# Create source parent and destination(or new) parent
tpm2 createprimary -C n -g sha256 -G rsa -c $new_parent_object -Q

tpm2 createprimary -C o -g sha256 -G rsa -c $source_parent_object -Q

# Create the restricted parent policy
tpm2 readpublic -c $new_parent_object -n $new_parent_name -Q

tpm2 startauthsession -S $policy_session

tpm2 policyduplicationselect -S $policy_session -N $new_parent_name \
-L $policy_duplication_select -Q

tpm2 flushcontext $policy_session

rm $policy_session

# Create the object to be duplicated using the policy
tpm2 create -C $source_parent_object -g sha256 -G rsa \
-r $duplicable_object_private -u $duplicable_object_public \
-L $policy_duplication_select -a "sensitivedataorigin|sign|decrypt" \
-c $duplicable_object -Q

# Satisfy the policy and duplicate the object
tpm2 readpublic -c $duplicable_object -n $duplicable_object_name -Q

tpm2 startauthsession -S $policy_session --policy-session

tpm2 policyduplicationselect -S $policy_session -N $new_parent_name \
-n $duplicable_object_name -Q

tpm2 duplicate -C $new_parent_object -c $duplicable_object -G null \
-p session:$policy_session -r $duplicated_object_private \
-s $duplicated_object_seed

tpm2 flushcontext $policy_session

rm $policy_session

# Attempt duplication to unintended parent
tpm2 createprimary -C n -g sha256 -G rsa -c $unintended_new_parent_object -Q

tpm2 readpublic -c $new_parent_object -n $unintended_new_parent_name -Q

tpm2 startauthsession -S $policy_session --policy-session

tpm2 policyduplicationselect -S $policy_session -N $unintended_new_parent_name \
-n $duplicable_object_name -Q

## Disable error reporting for expected failures to follow
trap - ERR

tpm2 duplicate -C $unintended_new_parent_object -c $duplicable_object -G null \
-p session:$policy_session -r $duplicated_object_private \
-s $duplicated_object_seed

## Restore error reporting
trap onerror ERR

tpm2 flushcontext $policy_session

rm $policy_session

exit 0
