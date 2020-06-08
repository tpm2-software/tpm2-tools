# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

get_new_clock() {
    tpm2 readclock > clock.yaml
    local clock=$(yaml_get_kv clock.yaml clock_info clock)

    # the magic number is enough time where where setting the clock to a point
    # in the future from where we read it.
    clock=$(($clock + 100000))
    echo -n $clock
}

cleanup() {
	tpm2 changeauth -c o -p newowner 2>/dev/null || true
	tpm2 changeauth -c p -p newplatform 2>/dev/null || true

	rm -f clock.yaml

	if [ "$1" != "no-shut-down" ]; then
		shut_down
	fi
}
trap cleanup EXIT

start_up

tpm2 setclock $(get_new_clock)

# validate hierarchies and passwords
tpm2 changeauth -c o newowner
tpm2 changeauth -c p newplatform

tpm2 setclock -c o -p newowner $(get_new_clock)
tpm2 setclock -c p -p newplatform $(get_new_clock)

exit 0
