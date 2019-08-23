# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
	rm -f clock.yaml
}
trap cleanup EXIT

start_up

tpm2_readclock > clock.yaml

# validate we can get each portion of the YAML file
yaml_get_kv clock.yaml time
yaml_get_kv clock.yaml clock_info clock
yaml_get_kv clock.yaml clock_info reset_count
yaml_get_kv clock.yaml clock_info restart_count
yaml_get_kv clock.yaml clock_info safe

exit 0
