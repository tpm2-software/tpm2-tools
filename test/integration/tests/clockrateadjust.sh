# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

cleanup() {
	tpm2_changeauth -c o -p newowner 2>/dev/null || true
	tpm2_changeauth -c p -p newplatform 2>/dev/null || true

	rm -f clock.yaml

	if [ "$1" != "no-shut-down" ]; then
		shut_down
	fi
}
trap cleanup EXIT

start_up

tpm2_clockrateadjust s
tpm2_clockrateadjust ss
tpm2_clockrateadjust sss

tpm2_clockrateadjust f
tpm2_clockrateadjust ff
tpm2_clockrateadjust fff

# validate hierarchies and passwords
tpm2_changeauth -c o newowner
tpm2_changeauth -c p newplatform

tpm2_clockrateadjust -c o -p newowner ss
tpm2_clockrateadjust -c p -p newplatform ff

trap - err

tpm2_clockrateadjust -c o -p newowner ssss
if [ $? -eq 0 ]; then
  echo "expected ssss to fail"
  exit 1
fi

tpm2_clockrateadjust -c o -p newowner sfss
if [ $? -eq 0 ]; then
  echo "expected ssss to fail"
  exit 1
fi

tpm2_clockrateadjust -c o -p newowner sfs
if [ $? -eq 0 ]; then
  echo "expected sfs to fail"
  exit 1
fi

tpm2_clockrateadjust -c o -p newowner qqq
if [ $? -eq 0 ]; then
  echo "expected qqq to fail"
  exit 1
fi

exit 0
