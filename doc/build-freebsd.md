FreeBSD build guide
======================
(updated for FreeBSD 12.0)

This guide describes how to build bitcoind and command-line utilities on FreeBSD.

This guide does not contain instructions for building the GUI.

## Preparation

You will need the following dependencies, which can be installed as root via pkg:

```bash
pkg install autoconf automake boost-libs git gmake libevent libtool pkgconf

git clone https://github.com/nationalbitcoin/russianbitcoin.git
```

See [dependencies.md](dependencies.md) for a complete overview.

### Building dependencies

Repository contains a set of preconfigured dependencies, you only need to build them.

**Important**: Use `gmake` (the non-GNU `make` will exit with an error).

```cd depends
gmake
```

This process may take a while.

## Building Russian Bitcoin Core

**Important**: Use `gmake` (the non-GNU `make` will exit with an error).

With wallet:
```bash
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-freebsd12/share/config.site ./configure --with-gui=no \
    BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" --prefix=$PWD/depends/x86_64-pc-freebsd12/ \
    BDB_CFLAGS="-I${BDB_PREFIX}/include" \
    MAKE=gmake
```

Without wallet:
```bash
./autogen.sh
./configure --with-gui=no --disable-wallet MAKE=gmake
```

followed by:

```bash
gmake # use -jX here for parallelism
```
