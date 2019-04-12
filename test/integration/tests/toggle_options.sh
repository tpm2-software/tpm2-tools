#!/bin/bash
#;**********************************************************************;
#
# Copyright (c) 2019, Sebastien LE STUM
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

# We don't need a TPM for this test, so unset the EXIT handler.
trap - EXIT

srcdir="$(readlink -e "$(dirname "$0")")"
toolsdir="$(readlink -e "${srcdir}"/../../../tools)"

# Provide a sanitizing test on whether a toggle
# is effectively taken into account on option parsing.
# Functionnal check is left for dedicated test cases.
#
# On failure, the function will print the information
# linked : toggle, filename, getopts string and case
# 
# Line header help in guessing what is wrong :
#   - <Y,!> : Getopt string is OK but no "case" was found
#   - <!,Y> : Getopt string do not contain toggle but "case" exist
#   - <!,!> : Option is declared but not used neither by "case" or "getopt"
#
# It assumes that the layout for describing toggles and
# option is coherent among the tools
function check_toggle() {
    toggle=${1}

    if [ ${#toggle} -ne 1 ]; then
        echo "toggle should be one character only !"
        exit 254
    fi

    for i in $(grep -R "'${toggle}'[[:space:]]*}" | sed "s%[[:space:]]*%%g"); do 
        optionnotfound=0
        casenotfound=0

        filename=${i%%:*}; 
        match=${i##*:}; 
        option="$(sed -r "s%.*'([^'])'.*%\1%g" <<< "${match}")"
        optionlist="$(grep -R "tpm2_options_new" "${filename}" | sed -r 's%.*("[^"]+").*%\1%g')"
        getcase="$(grep "case '${option}'" "${filename}" | sed "s%[[:space:]]*%%g")"

        if [[ "${filename}" =~ tpm2_options.c$ ]]; then
            continue
        fi

        if ! grep -q "${option}" <<< "${optionlist}"; then
            optionnotfound=1
            echo -n "<!,"
        fi

        if ! test -n "${getcase}"; then
            casenotfound=1
            echo -n "!> : "
        fi

        if [ ${casenotfound} -eq 0 ] && [ ${optionnotfound} -ne 0 ]; then
            echo -n "Y> : "
        fi

        if [ ${casenotfound} -ne 0 ] || [ ${optionnotfound} -ne 0 ]; then
            fail=1
            echo "${option} : ${filename} : ${match} : ${optionlist} : ${getcase%%:*}"
            echo "------"
        fi
    done
}

fail=0

# For each detected option toggle, check if it is actually declared to be used
for i in $(grep -rn "case '.'" "${toolsdir}"/*.c | cut -d"'" -f2-2 | sort | uniq); do 
    check_toggle "${i}"
done

exit $fail
