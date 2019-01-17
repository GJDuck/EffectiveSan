#!/bin/bash
#        __  __           _   _           ____
#   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
#  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
# |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
#  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
#
# Gregory J. Duck.
#
# Copyright (c) 2018 The National University of Singapore.
# All rights reserved.

BUILD_PLUGIN=no
VERSION=`cat VERSION`
LOWFAT_VERSION=be90b9106a09dde4e9bf9524f002d7db493643eb
RELEASE_NAME=effectivesan-$VERSION
BUILD_RELEASE=no
if [ $# = 1  -a "$1" = "release" ]
then
    BUILD_RELEASE=yes
fi

build_llvm()
{
    echo -e "${GREEN}$0${OFF}: copying the LowFat config files..."
    RUNTIME_PATH=llvm-4.0.1.src/projects/compiler-rt/lib/effective/
    INSTRUMENTATION_PATH=llvm-4.0.1.src/lib/Transforms/Instrumentation/
    CLANGLIB_PATH=llvm-4.0.1.src/tools/clang/lib/Basic/
    (cd config; cp lowfat_config.h lowfat_config.c ../${RUNTIME_PATH}/.)
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat_config.c" \
        "$PWD/$INSTRUMENTATION_PATH/lowfat_config.inc"
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat_config.h" \
        "$PWD/$INSTRUMENTATION_PATH/lowfat_config.h"
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat_config.h" \
        "$PWD/$CLANGLIB_PATH/lowfat_config.h"
    ln -fs "$PWD/${RUNTIME_PATH}/lowfat.h" \
        "$PWD/$INSTRUMENTATION_PATH/lowfat.h"

    BUILD_PATH=$1
    if [ -e $BUILD_PATH ]
    then
        CONFIGURE=false
        echo -e \
        "${GREEN}$0${OFF}: using existing LLVM build directory ($BUILD_PATH)..."
    else
        CONFIGURE=true
        echo -e \
        "${GREEN}$0${OFF}: creating LLVM build directory ($BUILD_PATH)..."
        mkdir -p $BUILD_PATH
    fi
    
    echo -e \
        "${GREEN}$0${OFF}: installing the LowFat ld script file..."
    mkdir -p $BUILD_PATH/lib/LowFat/
    cp config/lowfat.ld $BUILD_PATH/lib/LowFat/
    mkdir -p $BUILD_PATH/install/lib/LowFat/
    cp config/lowfat.ld $BUILD_PATH/install/lib/LowFat/
    
    echo -e "${GREEN}$0${OFF}: will now build LLVM..."
    cd $BUILD_PATH
    
    if [ $CONFIGURE = true ]
    then
        CC=$CLANG CXX=$CLANGXX cmake ../llvm-4.0.1.src/ \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=install \
            -DBUILD_SHARED_LIBS=ON \
            -DLLVM_TARGETS_TO_BUILD="X86" \
            -DLLVM_BUILD_TOOLS=OFF
    fi
    PARALLEL=`grep -c ^processor /proc/cpuinfo`
    make -j $PARALLEL install install-clang
    rm -rf "../$RELEASE_NAME"
    mv install "../$RELEASE_NAME"
    cd ..
    rm -rf install
    ln -s "$RELEASE_NAME" install
    echo

    echo -e "${GREEN}$0${OFF}: cleaning up the LowFat config files..."
    rm -f "$PWD/${RUNTIME_PATH}/lowfat_config.h" \
          "$PWD/${RUNTIME_PATH}/lowfat_config.c" \
          "$PWD/$INSTRUMENTATION_PATH/lowfat_config.inc" \
          "$PWD/$INSTRUMENTATION_PATH/lowfat_config.h" \
          "$PWD/$INSTRUMENTATION_PATH/lowfat.h" \
          "$PWD/$CLANGLIB_PATH/lowfat_config.h"
}

if [ -t 1 ]
then
    RED="\033[31m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    BOLD="\033[1m"
    OFF="\033[0m"
else
    RED=
    GREEN=
    YELLOW=
    BOLD=
    OFF=
fi

LOWFAT_SRC_ZIP=LowFat.zip
if [ ! -e "$LOWFAT_SRC_ZIP" ]
then
    echo -e "${GREEN}$0${OFF}: ${YELLOW}warning${OFF}: LowFat source code is \
missing!"
    echo -e "${GREEN}$0${OFF}: downloading LowFat.zip from GitHub..."
    wget -O "$LOWFAT_SRC_ZIP" \
        https://github.com/GJDuck/LowFat/archive/$LOWFAT_VERSION.zip
fi

echo -e "${GREEN}$0${OFF}: extracting LowFat files..."
yes | unzip "$LOWFAT_SRC_ZIP" LowFat-$LOWFAT_VERSION'/config/*' -d .
yes | unzip "$LOWFAT_SRC_ZIP" \
    LowFat-$LOWFAT_VERSION'/llvm-4.0.0.src/projects/compiler-rt/lib/lowfat/lowfat*' \
    -d .
mv -f LowFat-$LOWFAT_VERSION/config/ config
mv -f LowFat-$LOWFAT_VERSION/llvm-4.0.0.src/projects/compiler-rt/lib/lowfat/* \
    llvm-4.0.1.src/projects/compiler-rt/lib/effective/.

CMAKE=`which cmake`
if [ -z "$CMAKE" ]
then
    echo -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: cmake is not installed!"
    exit 1
fi

CLANG=`which clang-4.0`
CLANGXX=`which clang++-4.0`
LLVM_CONFIG=`which llvm-config-4.0`
HAVE_CLANG_4=false
if [ -z "$CLANG" -o -z "$CLANGXX" -o -z "$LLVM_CONFIG" ]
then
    echo -e \
        "${GREEN}$0${OFF}: ${YELLOW}warning${OFF}: clang-4.0 is not installed!"
    echo -e "${GREEN}$0${OFF}: will try the default clang."
    CLANG=`which gcc`
    CLANGXX=`which g++`
    if [ -z "$CLANG" -o -z "$CLANGXX" ]
    then
        echo -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: gcc is not installed!"
        exit 1
    fi
else
    HAVE_CLANG_4=true
fi

set -e

echo -e "${GREEN}$0${OFF}: building the LowFat config builder..."
(cd config; CC=$CLANG CXX=$CLANGXX make >/dev/null)

echo -e "${GREEN}$0${OFF}: building the LowFat config..."
CONFIG="--no-memory-alias --no-replace-std-malloc --no-replace-std-free \
    --no-protect sizes.cfg 64"
(cd config; ./lowfat-config $CONFIG > lowfat-config.log)

echo -e "${GREEN}$0${OFF}: building the LowFat config check..."
(cd config; CC=$CLANG CXX=$CLANGXX make lowfat-check-config >/dev/null)

echo -e "${GREEN}$0${OFF}: checking the LowFat config..."
if config/lowfat-check-config >/dev/null 2>&1
then
    CHECK=true
else
    CHECK=false
fi

if [ $CHECK != true ]
then
    echo -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: configuration check failed!"
    config/lowfat-check-config
    exit 1
fi

if [ $HAVE_CLANG_4 = false ]
then
    BOOTSTRAP_PATH=bootstrap
    CLANG_TMP="$PWD/$BOOTSTRAP_PATH/bin/clang"
    CLANGXX_TMP="$PWD/$BOOTSTRAP_PATH/bin/clang++"
    LLVM_CONFIG_TMP="$PWD/$BOOTSTRAP_PATH/bin/llvm-config"
    if [ ! -x "$CLANG_TMP" -o ! -x "$CLANGXX_TMP" -o ! -x "$LLVM_CONFIG_TMP" ]
    then
        echo -e \
        "${GREEN}$0${OFF}: clang-4.0 is not installed; bootstrapping LLVM..."
        build_llvm $BOOTSTRAP_PATH
    fi
    CLANG=$CLANG_TMP
    CLANGXX=$CLANGXX_TMP
    LLVM_CONFIG=$LLVM_CONFIG_TMP
    HAVE_CLANG_4=true
fi

BUILD_PATH=build
BUILD_PLUGIN=yes
BUILD_STANDALONE=yes
build_llvm $BUILD_PATH

echo -e "${GREEN}$0${OFF}: building test program..."
(cd test; make clean >/dev/null 2>&1; make >/dev/null 2>&1)

echo -n -e "${GREEN}$0${OFF}: testing EffectiveSan build..."
if test/Test >test.tmp 2>&1
then
    TEST_PASSED=true
else
    TEST_PASSED=false
fi
sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g" < test.tmp > test.log
rm -f test.tmp
(cd test; make clean >/dev/null 2>&1)
if [ $TEST_PASSED = true ]
then
    echo "ok"
else
    echo "failed!"
    echo -n -e "${GREEN}$0${OFF}: ${RED}ERROR${OFF}: EffectiveSan failed to \
build correctly (see test.log for more information)"
    exit 1
fi

echo -e "${GREEN}$0${OFF}: copying release files..."
cp README.md install
mkdir -p install/test
sed 's/install\///g' test/Makefile > install/test/Makefile
cp test/Test.cpp install/test
cp test/Test.h install/test
cp test/Shared.cpp install/test
cp test/Example.cpp install/test
cp test/Hijack.cpp install/test
if [ -d firefox ]
then
    mkdir -p install/firefox
    sed 's/install\///g' firefox/mozconfig > install/firefox/mozconfig
    cp firefox/effective.blacklist install/firefox
    cp firefox/firefox-52.2.1esr.patch install/firefox
    cp firefox/setup-firefox-build.sh install/firefox
fi
if [ -d spec2006 ]
then
    mkdir -p install/spec2006
    cp spec2006/run-spec2006.sh install/spec2006
    cp spec2006/cpu2006.patch install/spec2006
fi

if [ $BUILD_RELEASE = yes ]
then
    echo -e "${GREEN}$0${OFF}: building release package..."
    rm -f "$RELEASE_NAME.tar.xz"
    tar cvJ --owner root --group root -f "$RELEASE_NAME.tar.xz" "$RELEASE_NAME"
fi

echo -e "${GREEN}$0${OFF}: build is complete!"
echo -e "${GREEN}$0${OFF}: clang with EffectiveSan is available here: \
$PWD/bin/clang"
echo -e "${GREEN}$0${OFF}: clang++ with EffectiveSan is available here: \
$PWD/bin/clang++"
echo -e "${YELLOW}"
echo "        __  __           _   _           ____"
echo "   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __"
echo "  / _ \\ |_| |_ / _ \\/ __| __| \\ \\ / / _ \\___ \\ / _\` | \'_ \\"
echo " |  __/  _|  _|  __/ (__| |_| |\\ V /  __/___) | (_| | | | |"
echo "  \\___|_| |_|  \\___|\\___|\\__|_| \\_/ \\___|____/ \\__,_|_| |_|"
echo -e "${OFF}"
echo "USAGE:"
echo -e "${BOLD}      $PWD/$RELEASE_NAME/bin/clang -fsanitize=lowfat program.c${OFF}"
echo -e "${BOLD}      $PWD/$RELEASE_NAME/bin/clang++ -fsanitize=lowfat program.cpp${OFF}"
echo
echo "EXAMPLE:"
echo -e "${BOLD}      \$ cd test${OFF}"
echo -e "${BOLD}      \$ $PWD/$RELEASE_NAME/bin/clang++ -fsanitize=effective -O2 Example.cpp${OFF}"
echo -e "${BOLD}      \$ ./a.out${OFF}"
echo

