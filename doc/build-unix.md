UNIX BUILD NOTES
====================
Some notes on how to build Russian Bitcoin Core in Unix.

(For FreeBSD specific instructions, see `build-freebsd.md` in this directory.)

To Build
---------------------

```bash
git clone https://github.com/nationalbitcoin/russianbitcoin
cd russianbitcoin/depends
make
cd ..
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure --prefix=CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/
make # Use -jN for parallel building
make install # optional
```

This will build russianbitcoin-qt as well, if the dependencies are met.

Dependencies
---------------------

See [dependencies.md](dependencies.md)

Memory Requirements
--------------------

C++ compilers are memory-hungry. It is recommended to have at least 1.5 GB of
memory available when compiling Russian Bitcoin Core. On systems with less, gcc can be
tuned to conserve memory with additional CXXFLAGS:


    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure CXXFLAGS="--param ggc-min-expand=1 --param ggc-min-heapsize=32768" --prefix=$PWD/depends/x86_64-pc-linux-gnu/

Alternatively, or in addition, debugging information can be skipped for compilation. The default compile flags are
`-g -O2`, and can be changed with:

    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure CXXFLAGS="-O2" --prefix=$PWD/depends/x86_64-pc-linux-gnu/

Finally, clang (often less resource hungry) can be used instead of gcc, which is used by default:

    CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure CXX=clang++ CC=clang --prefix=$PWD/depends/x86_64-pc-linux-gnu/

## Linux Distribution Specific Instructions

### Ubuntu & Debian

Build requirements:

    sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils python3

### Fedora

Build requirements:

    sudo dnf install gcc-c++ libtool make autoconf automake python3

Notes
-----
The release is built with GCC and then "strip russianbitcoind" to strip the debug
symbols, which reduces the executable size by about 90%.


Security
--------
To help make your Russian Bitcoin Core installation more secure by making certain attacks impossible to
exploit even if a vulnerability is found, binaries are hardened by default.
This can be disabled with:

Hardening Flags:

	--enable-hardening --disable-hardening


Hardening enables the following features:
* _Position Independent Executable_: Build position independent code to take advantage of Address Space Layout Randomization
    offered by some kernels. Attackers who can cause execution of code at an arbitrary memory
    location are thwarted if they don't know where anything useful is located.
    The stack and heap are randomly located by default, but this allows the code section to be
    randomly located as well.

    On an AMD64 processor where a library was not compiled with -fPIC, this will cause an error
    such as: "relocation R_X86_64_32 against `......' can not be used when making a shared object;"

    To test that you have built PIE executable, install scanelf, part of paxutils, and use:

    	scanelf -e ./russianbitcoind

    The output should contain:

     TYPE
    ET_DYN

* _Non-executable Stack_: If the stack is executable then trivial stack-based buffer overflow exploits are possible if
    vulnerable buffers are found. By default, Russian Bitcoin Core should be built with a non-executable stack,
    but if one of the libraries it uses asks for an executable stack or someone makes a mistake
    and uses a compiler extension which requires an executable stack, it will silently build an
    executable without the non-executable stack protection.

    To verify that the stack is non-executable after compiling use:
    `scanelf -e ./russianbitcoin`

    The output should contain:
	STK/REL/PTL
	RW- R-- RW-

    The STK RW- means that the stack is readable and writeable but not executable.

Disable-wallet mode
--------------------
When the intention is to run only a P2P node without a wallet, Russian Bitcoin Core may be compiled in
disable-wallet mode with:

    --disable-wallet

In this case there is no dependency on Berkeley DB 4.8.

Mining is also possible in disable-wallet mode using the `getblocktemplate` RPC call.

Additional Configure Flags
--------------------------
A list of additional configure flags can be displayed with:

    ./configure --help

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.
