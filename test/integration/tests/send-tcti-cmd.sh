# SPDX-License-Identifier: BSD-3-Clause

# skip if tcti-cmd not installed
pkg-config --exists tss2-tcti-cmd
if [ $? -ne 0 ]; then
  exit 077
fi

source helpers.sh

start_up

random="$(tpm2 getrandom -T"cmd:tpm2 send" --hex 32)"

count="$(echo -n "$random" | wc -c)"

test "$count" -eq 64

exit 0
