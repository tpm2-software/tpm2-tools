# SPDX-License-Identifier: BSD-3-Clause
set -e

result=$(${abs_builddir}/tools/tpm2 getcap \
    --tcti='cmd:${abs_srcdir}/test/scripts/echo_tcti.py 8001000000170000000001000001000000000100000003' \
    --ignore-moredata vendor)
test ${result} == "0000000100000003"
