#!/bin/bash

# Checkout 4.X integration test directory
make clean; make distclean
git stash
curr_branch=$(git status | grep "On branch" | sed 's/On branch//g')
testcompatbranch=$RANDOM
git checkout 4.3.0
git checkout -b $testcompatbranch
git checkout $curr_branch
git checkout $testcompatbranch test/integration/tests
git branch -D $testcompatbranch

#
# RSA OAEP decryption was enabled as a feature after 4.X and so testing it
# would signal a false compatibility test failure.
#
git checkout HEAD test/integration/tests/rsadecrypt.sh
#
# tpm2_getekcertificate is known to break backwards compatibility
#
git checkout HEAD test/integration/tests/getekcertificate.sh

#
# Beyond 4.X release, the tpm2-tools were combined into a single
# busybox style binary "tpm2". The following makes adjustments
# to the tool-name which essentially invokes the same tools.
#
# Also, symlink is an irrelevant test for 4.X branch.
#
for f in `find test/integration/tests -iname '*.sh' | grep -v symlink`
do
    for i in `find tools -iname 'tpm2*.c'`
    do
        test=$(basename $i .c)
        replace=$(basename $i .c | sed  's/tpm2_//g')
        sed -i "s/$test/tpm2 $replace/g" $f
    done
done

./bootstrap; ./configure --enable-unit; make -j8 ; make check -j8
