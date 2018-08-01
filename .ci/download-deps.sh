#!/usr/bin/env bash
#;**********************************************************************;
#
# Copyright (c) 2017, Intel Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of Intel Corporation nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;

function get_deps() {

	echo "pwd starting: `pwd`"
	pushd "$1"
	echo "pwd clone tss: `pwd`"
	git clone https://github.com/tpm2-software/tpm2-tss.git --depth=1
	pushd tpm2-tss
	git fetch --tags
	git checkout 2.0.0 -b release-2.0.0
	echo "pwd build tss: `pwd`"
	./bootstrap
	./configure
	make -j$(nproc)
	make install
	popd
	echo "pwd done tss: `pwd`"

	echo "pwd clone abrmd: `pwd`"
	git clone https://github.com/tpm2-software/tpm2-abrmd.git --depth=1
	pushd tpm2-abrmd
	git fetch --tags
	git checkout 2.0.1 -b release-2.0.1
	echo "pwd build abrmd: `pwd`"
	./bootstrap
	./configure
	make -j$(nproc)
	make install
	popd
	echo "pwd done abrmd: `pwd`"
	popd
	echo "pwd done: `pwd`"
}
