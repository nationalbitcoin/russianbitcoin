# MacOS Deployment

The `macdeployqtplus` script should not be run manually. Instead, after building as usual:

```bash
make deploy
```

During the deployment process, the disk image window will pop up briefly
when the fancy settings are applied. This is normal, please do not interfere,
the process will unmount the DMG and cleanup before finishing.

When complete, it will have produced `RussianBitcoin-Qt.dmg`.

## SDK Extraction

`Xcode.app` is packaged in a `.xip` archive.
This makes the SDK less-trivial to extract on non-macOS machines.
One approach (tested on Debian Buster) is outlined below:

```bash

apt install clang cpio git liblzma-dev libxml2-dev libssl-dev make

git clone https://github.com/tpoechtrager/xar
pushd xar/xar
./configure
make
make install
popd

git clone https://github.com/NiklasRosenstein/pbzx
pushd pbzx
clang -llzma -lxar pbzx.c -o pbzx -Wl,-rpath=/usr/local/lib
popd

xar -xf Xcode_10.2.1.xip -C .

./pbzx/pbzx -n Content | cpio -i

find Xcode.app -type d -name MacOSX.sdk -execdir sh -c 'tar -c MacOSX.sdk/ | gzip -9n > /MacOSX10.14.sdk.tar.gz' \;
```

on macOS the process is more straightforward:

```bash
xip -x Xcode_10.2.1.xip
tar -C Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/ -czf MacOSX10.14.sdk.tar.gz MacOSX.sdk
```

Our previously used macOS SDK (`MacOSX10.11.sdk`) can be extracted from
[Xcode 7.3.1 dmg](https://developer.apple.com/devcenter/download.action?path=/Developer_Tools/Xcode_7.3.1/Xcode_7.3.1.dmg).
The script [`extract-osx-sdk.sh`](./extract-osx-sdk.sh) automates this. First
ensure the DMG file is in the current directory, and then run the script. You
may wish to delete the `intermediate 5.hfs` file and `MacOSX10.11.sdk` (the
directory) when you've confirmed the extraction succeeded.

```bash
apt-get install p7zip-full sleuthkit
contrib/macdeploy/extract-osx-sdk.sh
rm -rf 5.hfs MacOSX10.11.sdk
```
