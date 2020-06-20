Russian Bitcoin Core
=============

Setup
---------------------
Russian Bitcoin Core is the original client and it builds the backbone of the network. It downloads and, by default, stores the entire history of transactions, which requires a few gigabytes of disk space.

To download Russian Bitcoin Core, visit [russianbitcoin.nationalbitcoin.org](http://russianbitcoin.nationalbitcoin.org/download/).

Running
---------------------
The following are some helpful notes on how to run Russian Bitcoin Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/russianbitcoin-qt` (GUI) or
- `bin/russianbitcoind` (headless)

### Windows

Unpack the files into a directory, and then run russianbitcoin-qt.exe.

### macOS

Drag Russian Bitcoin Core to your applications folder, and then run Russian Bitcoin Core.

Building
---------------------
The following are developer notes on how to build Russian Bitcoin Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [FreeBSD Build Notes](build-freebsd.md)

Development
---------------------
The repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Shared Libraries](shared-libraries.md)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [russianbitcoin.conf Configuration File](russianbitcoin-conf.md)
- [Files](files.md)
- [Tor Support](tor.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
