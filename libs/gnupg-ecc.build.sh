#!/bin/bash
STAMP=`date +%Y%m%d%H%M%S`
svn checkout http://gnupg-ecc.googlecode.com/svn/branches/ gnupg-ecc-$STAMP
rm gnupg-ecc
ln -s gnupg-ecc-$STAMP gnupg-ecc

mkdir -p ../bin/gnupg-ecc
pushd ../bin/gnupg-ecc
DEST=`pwd`
popd
pushd gnupg-ecc/gpg2ecc/libgpg-error && ./autogen.sh && ./configure --prefix=$DEST && make && make install && popd
pushd gnupg-ecc/gpg2ecc/libassuan && ./autogen.sh && ./configure --with-gpg-error-prefix=$DEST --prefix=$DEST && make && make install && popd
pushd gnupg-ecc/gpg2ecc/libgcrypt && ./autogen.sh && ./configure --with-gpg-error-prefix=$DEST --prefix=$DEST && make && make install && popd
