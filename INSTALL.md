## Building tpm2-tools

Below you will find instructions to build and install the tpm2-tools project.

### Download the Source
To obtain the tpm2-tools sources you must clone them as below:
```
git clone https://github.com/tpm2-software/tpm2-tools
```

### Dependencies

To build and install the tpm2-tools software the following software is required:

  * GNU Autoconf
  * GNU Automake
  * GNU Libtool
  * pkg-config
  * C compiler
  * C Library Development Libraries and Header Files (for pthreads headers)
  * ESAPI - TPM2.0 TSS ESAPI library (tss2-esys) and header files
  * OpenSSL libcrypto library and header files
  * Curl library and header files

#### Optional Dependencies:
  * To build the man pages you need [pandoc](https://github.com/jgm/pandoc)
  * To enable the new userspace resource manager, one must get tpm2-tabrmd
    (**recommended**).

### Typical Distro Dependency Installation

Here we are going to satisfy tpm2-tools dependencies with:
* tpm2-tss: <https://github.com/tpm2-software/tpm2-tss>
* tpm2-abrmd: <https://github.com/tpm2-software/tpm2-abrmd>
* TPM simulator: <https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm974.tar.gz>

Which are necessary for the build example section at the bottom of this file, we need to satisfy the dependencies for each item named above except for the simulator.

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

For more detailed information about the dependencies of tpm2-tss and tmp2-abrmd, please consult the corresponding links for each project.



### tpm2-tools TSS and ABRMD Dependency Version Chart

| tpm2-tools version | tpm2-tss version | tpm2-abrmd version|
|--------------------|------------------|-------------------|
|[master](https://github.com/tpm2-software/tpm2-tools)|[master](https://github.com/tpm2-software/tpm2-tss)|[master](https://github.com/tpm2-software/tpm2-abrmd)|
|[3.1.0](https://github.com/tpm2-software/tpm2-tools/releases/tag/3.1.0)|[2.0.0](https://github.com/tpm2-software/tpm2-tss/releases/tag/2.0.0)|[2.0.0](https://github.com/tpm2-software/tpm2-abrmd/tree/2.0.0)|
|[2.1.0](https://github.com/tpm2-software/tpm2-tools/releases/tag/2.1.0)|[1.2.0](https://github.com/tpm2-software/tpm2-tss/releases/tag/1.2.0)|[1.1.1](https://github.com/tpm2-software/tpm2-abrmd/releases/tag/1.1.1)|
|[df751ae](https://github.com/tpm2-software/tpm2.0-tools/tree/df751ae5bea0bb057c9ee4cb0c1176c48ff68492)(master)|[1.1.0](https://github.com/tpm2-software/TPM2.0-TSS/releases/tag/1.1.0)|[1.0.0](https://github.com/tpm2-software/tpm2-abrmd/releases/tag/1.0.0)|
|[v2.0.0](https://github.com/tpm2-software/tpm2.0-tools/releases/tag/2.0.0)|[1.0](https://github.com/tpm2-software/TPM2.0-TSS/releases/tag/1.0)|old resourcemgr|
|[v1.1.0](https://github.com/tpm2-software/tpm2.0-tools/releases/tag/v1.1.0)|[1.0](https://github.com/tpm2-software/TPM2.0-TSS/releases/tag/1.0)|old resourcemgr|
|[v1.1-beta_1](https://github.com/tpm2-software/tpm2.0-tools/releases/tag/v1.1-beta_1)|[1.0-beta_1](https://github.com/tpm2-software/TPM2.0-TSS/releases/tag/1.0-beta_1)|old resourcemgr|
|[v1.1-beta_0](https://github.com/tpm2-software/tpm2.0-tools/releases/tag/v1.1-beta_0)|[v1.0-beta_0](https://github.com/tpm2-software/TPM2.0-TSS/releases/tag/v1.0-beta_0)|old resourcemgr|
|[14a7ff5](https://github.com/tpm2-software/tpm2.0-tools/tree/14a7ff527bc0411c215bd9d575f2866e1f2e71cf)|[210b770](https://github.com/tpm2-software/TPM2.0-TSS/tree/210b770c1dff47b11be623e1d1e7ffb02298fca5)|old resourcemgr|
|[4b4cbea](https://github.com/tpm2-software/tpm2.0-tools/tree/4b4cbeafe30430f42826592dee2abafec818385f)|[d4f23cc](https://github.com/tpm2-software/TPM2.0-TSS/tree/d4f23cc25c4c0fb66dd36897d2fad8e1e37c6443)|old resourcemgr|
|[e8150e4](https://github.com/tpm2-software/tpm2.0-tools/tree/e8150e48dd47f761dff10583631b2a0a30ee4d90)|[60ec042](https://github.com/tpm2-software/TPM2.0-TSS/tree/60ec04237b5344666435e129bd85f7496a6a9985)|old resourcemgr|
|[84d5f26](https://github.com/tpm2-software/tpm2.0-tools/tree/84d5f262f281556c57f7ec2fba06eda3acadd26c)|[371fdbc](https://github.com/tpm2-software/TPM2.0-TSS/tree/371fdbc638c55b9ac8a0eaec9375dbca0412861c)|old resourcemgr|
|[v1.0.1](https://github.com/tpm2-software/tpm2.0-tools/releases/tag/v1.0.1)|[1.0-alpha_0](https://github.com/tpm2-software/TPM2.0-TSS/releases/tag/1.0-alpha_0)|old resourcemgr|

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
$ wget https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm974.tar.gz
$ tar -zxvf ibmtpm974.tar.gz
$ cd src
$ make -j5
```


And it's done, you are ready to run the projects.
