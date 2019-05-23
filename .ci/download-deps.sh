#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause

function get_deps() {

	echo "pwd starting: `pwd`"
	pushd "$1"
	echo "pwd clone tss: `pwd`"
	if [ ! -d tpm2-tss ]; then
		git clone --depth=1 https://github.com/tpm2-software/tpm2-tss.git
		pushd tpm2-tss
		echo "pwd build tss: `pwd`"
		./bootstrap
		./configure --disable-dependency-tracking CFLAGS=-g
		make -j4
		make install
		popd
		echo "pwd done tss: `pwd`"
	else
		echo "tss already downloaded/built/installed, skipping"
	fi

	if [ ! -d tpm2-abrmd ]; then
		echo "pwd clone abrmd: `pwd`"
		git clone --depth=1 https://github.com/tpm2-software/tpm2-abrmd.git
		pushd tpm2-abrmd
		echo "pwd build abrmd: `pwd`"
		./bootstrap
		./configure --disable-dependency-tracking CFLAGS=-g
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
