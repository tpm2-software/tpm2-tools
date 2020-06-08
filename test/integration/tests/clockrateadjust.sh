# SPDX-License-Identifier: BSD-3-Clause

source helpers.sh

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

tpm2 clockrateadjust s
tpm2 clockrateadjust ss
tpm2 clockrateadjust sss

tpm2 clockrateadjust f
tpm2 clockrateadjust ff
tpm2 clockrateadjust fff

# validate hierarchies and passwords
tpm2 changeauth -c o newowner
tpm2 changeauth -c p newplatform

tpm2 clockrateadjust -c o -p newowner ss
tpm2 clockrateadjust -c p -p newplatform ff

trap - err

tpm2 clockrateadjust -c o -p newowner ssss
if [ $? -eq 0 ]; then
  echo "expected ssss to fail"
  exit 1
fi

tpm2 clockrateadjust -c o -p newowner sfss
if [ $? -eq 0 ]; then
  echo "expected ssss to fail"
  exit 1
fi

tpm2 clockrateadjust -c o -p newowner sfs
if [ $? -eq 0 ]; then
  echo "expected sfs to fail"
  exit 1
fi

tpm2 clockrateadjust -c o -p newowner qqq
if [ $? -eq 0 ]; then
  echo "expected qqq to fail"
  exit 1
fi

exit 0
