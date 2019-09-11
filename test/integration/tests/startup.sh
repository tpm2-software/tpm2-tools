# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

tpm2_startup --clear

tpm2_startup

# rather than incur another simulator startup just test shutdown
# in this test as well.
tpm2_shutdown

tpm2_shutdown --clear

exit 0
