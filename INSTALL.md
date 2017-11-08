## Building tpm2-tools

Below you will find instructions to build and install the tpm2-tools project.

### Download the Source
To obtain the tpm2-tools sources you must clone them as below:
```
git clone https://github.com/01org/tpm2-tools
```

### Dependencies

To build and install the tpm2-tools software the following software is required:

  * GNU Autoconf
  * GNU Automake
  * GNU Libtool
  * pkg-config
  * C compiler
  * C Library Development Libraries and Header Files (for pthreads headers)
  * SAPI - TPM2.0 TSS SAPI library and header files
  * OpenSSL libcrypto library and header files
  * Curl library and header files

#### Optional Dependencies:
  * To build the man pages you need [md2man-roff](https://github.com/sunaku/md2man)
  * To enable the new userspace resource manager, one must get tpm2-tabrmd
    (**recommended**).

### Typical Distro Dependency Installation

#### Ubuntu 16.04

Satisfying the dependencies for tpm2-tools falls into two general steps, stuff
you can easily get via the package manager, and stuff you cannot.

**NOTE**: The *tpm2 Userspace Dependencies* may not be the correct version in
your distros package manager.

**Packages**:

The packages in the below command can be ascertained via the package manager.

```
sudo apt-get install autoconf automake libtool pkg-config gcc libssl-dev \
    libcurl4-gnutls-dev
```
**Notes**:

  * One can substitute gcc for clang if they desire.
  * On pre-ubuntu 16.04 `libcurl4-gnutls-dev` was provided by `libcurl-dev`
    * The libcurl dependency can be satisfied in many ways, and likely change
      with Ubuntu versions:
      * `libcurl4-openssl-dev 7.47.0-1ubuntu2.2`
      * `libcurl4-nss-dev 7.47.0-1ubuntu2.2`
      * `libcurl4-gnutls-dev 7.47.0-1ubuntu2.2`

**tpm2 Userspace Dependencies**:

The following tpm2 userspace dependencies can be satisfied by getting the
source, building and installing them. They can be located here:

  * SAPI - The low level system API: <https://github.com/01org/tpm2-tss>
  * ABRMD (**recommended but optional**) - Which is the userspace resource
    manager: <https://github.com/01org/tpm2-abrmd>

**Other Dependencies**

To get md2man-roff, see there page at: <https://github.com/sunaku/md2man>


### tpm2-tools SAPI and ABRMD Dependency Version Chart

| tpm2-tools version | tpm2-tss version | tpm2-abrmd version|
|--------------------|------------------|-------------------|
|[master](https://github.com/01org/tpm2-tools)|[master](https://github.com/01org/tpm2-tss)|[master](https://github.com/01org/tpm2-abrmd)|
|[2.1.0](https://github.com/01org/tpm2-tools/releases/tag/2.1.0)|[1.2.0](https://github.com/01org/tpm2-tss/releases/tag/1.2.0)|[1.1.1](https://github.com/01org/tpm2-abrmd/releases/tag/1.1.1)|
|[df751ae](https://github.com/01org/tpm2.0-tools/tree/df751ae5bea0bb057c9ee4cb0c1176c48ff68492)(master)|[1.1.0](https://github.com/01org/TPM2.0-TSS/releases/tag/1.1.0)|[1.0.0](https://github.com/01org/tpm2-abrmd/releases/tag/1.0.0)|
|[v2.0.0](https://github.com/01org/tpm2.0-tools/releases/tag/2.0.0)|[1.0](https://github.com/01org/TPM2.0-TSS/releases/tag/1.0)|old resourcemgr|
|[v1.1.0](https://github.com/01org/tpm2.0-tools/releases/tag/v1.1.0)|[1.0](https://github.com/01org/TPM2.0-TSS/releases/tag/1.0)|old resourcemgr|
|[v1.1-beta_1](https://github.com/01org/tpm2.0-tools/releases/tag/v1.1-beta_1)|[1.0-beta_1](https://github.com/01org/TPM2.0-TSS/releases/tag/1.0-beta_1)|old resourcemgr|
|[v1.1-beta_0](https://github.com/01org/tpm2.0-tools/releases/tag/v1.1-beta_0)|[v1.0-beta_0](https://github.com/01org/TPM2.0-TSS/releases/tag/v1.0-beta_0)|old resourcemgr|
|[14a7ff5](https://github.com/01org/tpm2.0-tools/tree/14a7ff527bc0411c215bd9d575f2866e1f2e71cf)|[210b770](https://github.com/01org/TPM2.0-TSS/tree/210b770c1dff47b11be623e1d1e7ffb02298fca5)|old resourcemgr|
|[4b4cbea](https://github.com/01org/tpm2.0-tools/tree/4b4cbeafe30430f42826592dee2abafec818385f)|[d4f23cc](https://github.com/01org/TPM2.0-TSS/tree/d4f23cc25c4c0fb66dd36897d2fad8e1e37c6443)|old resourcemgr|
|[e8150e4](https://github.com/01org/tpm2.0-tools/tree/e8150e48dd47f761dff10583631b2a0a30ee4d90)|[60ec042](https://github.com/01org/TPM2.0-TSS/tree/60ec04237b5344666435e129bd85f7496a6a9985)|old resourcemgr|
|[84d5f26](https://github.com/01org/tpm2.0-tools/tree/84d5f262f281556c57f7ec2fba06eda3acadd26c)|[371fdbc](https://github.com/01org/TPM2.0-TSS/tree/371fdbc638c55b9ac8a0eaec9375dbca0412861c)|old resourcemgr|
|[v1.0.1](https://github.com/01org/tpm2.0-tools/releases/tag/v1.0.1)|[1.0-alpha_0](https://github.com/01org/TPM2.0-TSS/releases/tag/1.0-alpha_0)|old resourcemgr|

## Building

To compile tpm2-tools execute the following commands from the root of the
source directory:
```
$ ./bootstrap
$ ./configure
$ make
```

This is sufficient for running as long as you alter `PATH` so that it points to
the *tools* directory, or just execute them via a full path.

For Example:

```
./tools/tpm2_getrandom 4
```

## Installing

For those who wish to install, one can execute:

```
$ sudo make install
```
