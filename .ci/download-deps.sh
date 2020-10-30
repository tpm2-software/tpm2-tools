#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

function get_deps() {

	TSS_VERSION=${TPM2_TSS_VERSION:-3.0.1}
	ABRMD_VERSION=2.3.3

	echo "pwd starting: `pwd`"
	if [ "$TSS_VERSION" = "2.4.0" ]; then
		if [ "$DOCKER_IMAGE" = "fedora-30" ]; then
			yum -y install libgcrypt-devel
		elif [ "$DOCKER_IMAGE" = "opensuse-leap" ]; then
			zypper -n in libgcrypt-devel
		elif [ "$DOCKER_IMAGE" = "ubuntu-20.04" -o "$DOCKER_IMAGE" = "ubuntu-18.04" ]; then
			apt-get -y install libgcrypt20-dev
		fi
	fi
	pushd "$1"
	echo "pwd clone tss: `pwd`"
	if [ ! -d tpm2-tss ]; then
		git clone --depth=1 \
		--branch "$TSS_VERSION" https://github.com/tpm2-software/tpm2-tss.git
		pushd tpm2-tss
		echo "pwd build tss: `pwd`"
		./bootstrap
		./configure CFLAGS=-g
		make -j4
		make install
		popd
		echo "pwd done tss: `pwd`"
	else
		echo "tss already downloaded/built/installed, skipping"
	fi

	if [ ! -d tpm2-abrmd ]; then
		echo "pwd clone abrmd: `pwd`"
		git clone --depth=1 \
		--branch "$ABRMD_VERSION" https://github.com/tpm2-software/tpm2-abrmd.git
		pushd tpm2-abrmd
		echo "pwd build abrmd: `pwd`"
		./bootstrap
		./configure CFLAGS=-g
		make -j4
		make install
		popd
		echo "pwd done abrmd: `pwd`"
		popd
		echo "pwd done: `pwd`"
	else
		echo "abrmd already downloaded/built/installed, skipping"
	fi

}
