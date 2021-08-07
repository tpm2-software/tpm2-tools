## Building tpm2-tools

Below you will find instructions to build and install the tpm2-tools project.

### Download the Source
To obtain the tpm2-tools sources you must clone them as below:
```
git clone https://github.com/tpm2-software/tpm2-tools
```

### Dependencies

To build and install the tpm2-tools software the following software is required:

  * GNU Autoconf (version >= 2019.01.06)
  * GNU Automake
  * GNU Libtool
  * pkg-config
  * C compiler
  * C Library Development Libraries and Header Files (for pthreads headers)
  * ESAPI - TPM2.0 TSS ESAPI library (tss2-esys) and header files
  * OpenSSL libcrypto library and header files (version >= 1.1.0)
  * Curl library and header files

#### Optional Dependencies:
  * To build the man pages you need [pandoc](https://github.com/jgm/pandoc)
  * FAPI - TPM2.0 TSS FAPI library (tss2-fapi) and header files
  * To enable the new userspace resource manager, one must get tpm2-tabrmd
    (**recommended**).
  * When ./configure is invoked with --enable-unit or --enable-unit=abrmd,
    the tests are run towards a resource manager, tpm2-abrmd, which must be on $PATH.
  * When ./configure is invoked with --enable-unit=mssim, the tests are run directly
    towards tpm_server, without resource manager.
  * For the tests, with or without resource manager, tpm_server must be installed.
  * Some tests pass only if xxd, expect, bash and python with PyYAML are available
  * Some tests optionally use (but do not require) curl

### Typical Distro Dependency Installation

Here we are going to satisfy tpm2-tools dependencies with:
* tpm2-tss: <https://github.com/tpm2-software/tpm2-tss>
* tpm2-abrmd: <https://github.com/tpm2-software/tpm2-abrmd>
* TPM simulator: <https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1332.tar.gz>

Which are necessary for the build example section at the bottom of this file, we need to satisfy the dependencies for each item named above except for the simulator.

#### Ubuntu 16.04

Satisfying the dependencies for tpm2-tools falls into two general steps, stuff
you can easily get via the package manager, and stuff you cannot.

**NOTE**: The *tpm2 Userspace Dependencies* may not be the correct version in
your distros package manager.

**Packages**:

The packages in the below command can be ascertained via the package manager.

```
sudo apt-get install autoconf automake libtool pkg-config gcc \
    libssl-dev libcurl4-gnutls-dev python-yaml
```
**Notes**:

  * One can substitute gcc for clang if they desire.
  * On pre-ubuntu 16.04 `libcurl4-gnutls-dev` was provided by `libcurl-dev`
    * The libcurl dependency can be satisfied in many ways, and likely change
      with Ubuntu versions:
      * `libcurl4-openssl-dev 7.47.0-1ubuntu2.2`
      * `libcurl4-nss-dev 7.47.0-1ubuntu2.2`
      * `libcurl4-gnutls-dev 7.47.0-1ubuntu2.2`
  * One needs autoconf archive, which is too old in the packagemanager. You can get
    working version from [here](http://ftpmirror.gnu.org/autoconf-archive/autoconf-archive-2019.01.06.tar.xz)

**tpm2 Userspace Dependencies**:

The following tpm2 userspace dependencies can be satisfied by getting the
source, building and installing them. They can be located here:

  * ESAPI - The enhanced system API: <https://github.com/tpm2-software/tpm2-tss>
  * ABRMD (**recommended but optional**) - Which is the userspace resource
    manager: <https://github.com/tpm2-software/tpm2-abrmd>



#### Fedora


In case you want to build from source the next command block should cover all the dependencies for tpm2-tools, the enhanced system API (tpm2-tss) and the userspace resource manager (tpm2-abrmd).

```
$ sudo dnf -y update && sudo dnf -y install automake libtool \
autoconf autoconf-archive libstdc++-devel gcc pkg-config \
uriparser-devel libgcrypt-devel dbus-devel glib2-devel \
compat-openssl10-devel libcurl-devel PyYAML

```
Some distros have the dependencies already packaged, you can simply install the package that contains the needed build requirements.

```
$ sudo dnf builddep tpm2-tools

```

The package installed above contains all the dependencies for tpm2-tools included the projects mentioned at the beginning of this section (tpm2-tss and tpm2-abrmd)

For more detailed information about the dependencies of tpm2-tss and tmp2-abrmd, please consult the corresponding links for each project. You can find these links in
the [Dependency-Matrix](https://tpm2-software.github.io/versions/)

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

### Building from source example


Now we can start building the projects, there are four major steps for building the projects from source:
#### Bootstrapping the build

With the bootstrap command we run a script which generates the list of source files along with the configure script.

In the project directory:

```
$  ./bootstrap
```

#### Configuring the build

Here we run the configure script, this generates the makefiles needed for the compilation.

```
$ ./configure
```

Depending of the project, you can add additional information to the configure script, please refer to the links provided below for more information about the custom options.

* Default values for GNU installation directories: <https://www.gnu.org/prep/standards/html_node/Directory-Variables.html>
* Custom options for tpm2-tss: <https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md>
* Custom options for tpm2-abrmd: <https://github.com/tpm2-software/tpm2-abrmd/blob/master/INSTALL.md>

#### Compiling the Libraries

We use the make command for compile the code.

```
$ make -j$(nproc)
```


#### Installing the Libraries

Once we have finish building the projects it's time to install them.

```
$ sudo make install
```
Now putting all together:

* ##### Tpm2-tss
```
$ git clone https://github.com/tpm2-software/tpm2-tss.git
$ cd tpm2-tss
$ ./bootstrap
$ ./configure --prefix=/usr
$ make -j5
$ sudo make install
```

* ##### Tpm2-abrmd
```
$ git clone https://github.com/tpm2-software/tpm2-abrmd.git
$ cd tpm2-abrmd
$ ./bootstrap
$ ./configure --with-dbuspolicydir=/etc/dbus-1/system.d
--with-udevrulesdir=/usr/lib/udev/rules.d
--with-systemdsystemunitdir=/usr/lib/systemd/system
--libdir=/usr/lib64 --prefix=/usr
$ make -j5
$ sudo make install
```

* ##### Tpm2-tools
```
$ git clone https://github.com/tpm2-software/tpm2-tools.git
$ cd tpm2-tools
$ ./bootstrap
$ ./configure --prefix=/usr
$ make -j5
$ sudo make install
```
* ##### TPM simulator
```
$ mkdir ibmtpm && cd ibmtpm
$ wget https://sourceforge.net/projects/ibmswtpm2/files/latest/download -O ibmtpm.tar.gz
$ tar -zxvf ibmtpm.tar.gz
$ cd src
$ make -j5
```


And it's done, you are ready to run the projects.
