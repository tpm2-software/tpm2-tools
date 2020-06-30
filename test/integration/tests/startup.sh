# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

start_up

tpm2 startup --clear

tpm2 startup

# rather than incur another simulator startup just test shutdown
# in this test as well.
tpm2 shutdown

tpm2 shutdown --clear

exit 0
