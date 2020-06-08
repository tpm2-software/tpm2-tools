# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

# We don't need a TPM for this test, so unset the EXIT handler.
trap - EXIT

# Since this only tests tools options and docs
# and is not portable skip it on FreeBSD
if [ "$OS" == "FreeBSD" ]; then
    exit 0
fi

srcdir="$(readlink -e "$(dirname "$0")")"
toolsdir="$(readlink -e "${srcdir}"/../../../tools)"
mandir="$(readlink -e "${srcdir}"/../../../man)"


# Provide a sanitizing test on whether a toggle
# is effectively taken into account on option parsing.
# Also, checks if the options are documented in the
# respective man file consistently.
# Functionnal check is left for dedicated test cases.
#
# It assumes that the layout for describing toggles and
# option is coherent among the tools
function check_toggle() {
    toggle=${1}

    if [ ${#toggle} -ne 1 ]; then
        echo "toggle should be one character only !"
        exit 254
    fi

    for i in $(grep "'${toggle}'[[:space:]]*}" "${toolsdir}"/*.c | \
    sed "s%[[:space:]]*%%g"); do
        # An example:
        # i:     tools/tpm2_nvdefine.c:{"hierarchy",required_argument,NULL,'a'},
        # filename:    tools/tpm2_nvdefine.c
        # match:       {"hierarchy",required_argument,NULL,'a'},
        # option:      a
        # option_long: hierarchy
        # optionlist:  "x:a:s:b:P:p:L:"
        # getcase:     case'a':

        filename=${i%%:*};
        match=${i##*:};
        option="$(sed -r "s%.*'([^'])'.*%\1%g" <<< "${match}")"
        option_long="$(grep -oP '(?<={").*(?=")' <<< "${match}")"
        optionlist="$(grep -R "tpm2_options_new" "${filename}" | \
        sed -r 's%.*("[^"]+").*%\1%g')"
        getcase="$(grep "case '${option}'" "${filename}" | \
        sed "s%[[:space:]]*%%g")"

        echo "filename: $filename"
        echo "    match:        $match"
        echo "    option:       $option"
        echo "    option_long:  $option_long"
        echo "    optionlist:   $optionlist"
        echo "    getcase:      $getcase"

        if [[ "${filename}" =~ tpm2_options.c$ ]]; then
            continue
        fi

        if ! grep -q "${option}" <<< "${optionlist}"; then
            echo "$filename: option -$option (--$option_long) not found in \
            option list $optionlist"
            exit 1
        fi

        if ! test -n "${getcase}"; then
            echo "$filename: switch case '$option' not found for option \
            -$option (--$option_long)"
            exit 1
        fi

        ####################### check man page #######################
        man_filename="$(basename $filename)"            # tpm2_nvdefine.c
        man_filename="$mandir/${man_filename%.*}.1.md"  # man/tpm2_nvdefine.1.md
        man=$(cat "$man_filename")

        # resolve markdown includes
        man_resolved="$man"
        for md_include in $(grep -Po '(?<=\]\()common/.*(?=\))' <<< "$man"); do
            man_resolved="$man_resolved $(cat $mandir/$md_include)"
        done

        # search markdown for option (short and long)
        man_opt=$(grep -oe "\*\*-$option\*\*, \*\*\\\--$option_long\*\*" \
        <<< "$man_resolved") || true

        if [ -n "$man_opt" ]; then
            echo "    man_opt:      $man_opt"
        else
            echo "$filename: missing option -$option/--$option_long in \
            $man_filename"
            exit 1
        fi
    done
}

fail=0

# For each detected option toggle, check if it is actually declared to be used
# and documented
for i in $(grep -rn "case '.'" "${toolsdir}"/*.c | \
cut -d"'" -f2-2 | sort | uniq); do
    check_toggle "${i}"
done

# For each documented option toggle in the man pages, look if it is present in
# the code
for j in $(grep -oe "\*\*-.\*\*, \*\*\\\--.*\*\*" "${mandir}"/*.1.md | \
sed -r 's/\s//g' ); do
    filename=${j%%:*};
    option="$(grep -oP '(?<=\*\*-).(?=\*\*)' <<< "$j")"
    option_long="$(grep -oP '(?<=\*\*\\\--).*(?=\*\*)' <<< "$j")"

    c_filename=$(basename ${filename%.1.md}).c

    echo "$filename: looking for -$option (--$option_long) in $c_filename"
    found=$(grep -r "case '${option}'" "$toolsdir" --include="$c_filename") \
    || true

    if [ -z "$found" ]; then
        echo "$filename: missing option -$option (--$option_long) in \
        $c_filename"
        exit 1
    fi
done

exit $fail
