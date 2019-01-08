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

set -e

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

if [ ! -d "firefox-52.2.1esr" ]
then
    if [ ! -f "firefox-52.2.1esr.source.tar.xz" ]
    then
	    echo -e "${GREEN}$0${OFF}: downloading FireFox source code..."
        wget -O "firefox-52.2.1esr.source.tar.xz" https://ftp.mozilla.org/pub/firefox/releases/52.2.1esr/source/firefox-52.2.1esr.source.tar.xz
    fi
	echo -e "${GREEN}$0${OFF}: unpacking FireFox source code..."
	sleep 1
	tar xvfJ "firefox-52.2.1esr.source.tar.xz"
	echo -e "${GREEN}$0${OFF}: patching FireFox source code..."
	patch -p0 < firefox-52.2.1esr.patch
fi

if [ ! -e "firefox-52.2.1esr/mozconfig" ]
then
    echo -e "${GREEN}$0${OFF}: setting up mozconfig..."
    cp mozconfig "firefox-52.2.1esr/mozconfig"
fi

if [ ! -e "firefox-52.2.1esr/effective.blacklist" ]
then
    echo -e "${GREEN}$0${OFF}: setting up effective.blacklist..."
    cp effective.blacklist "firefox-52.2.1esr/effective.blacklist"
fi

if ! dpkg -l libvpx-dev >/dev/null 2>&1
then
    echo -e "${GREEN}$0${OFF}: setting up libvpx-dev..."
    sudo apt-get install libvpx-dev
fi

echo
echo "The EffectiveSan FireFox configuration has been setup.  To build, run the "
echo "following commands:"
echo
echo "    $ cd firefox-52.2.1esr"
echo "    $ ./mach build"
echo
echo "If the build was successful, then you can run FireFox using the command:"
echo
echo "    $ ./mach run"
echo
echo -e "${YELLOW}DISCLAIMER${OFF}:"
echo
echo "The FireFox build is primarily intended to be a proof-of-concept."
echo
echo -e "The build is ${BOLD}not${OFF} intended to be stable, and has not been extensively tested."
echo "Some websites, such as <youtube.com>, are known to break the build, whereas"
echo "most others seem stable.  The build may behave differently on different"
echo "machines."
echo
echo "As noted in the paper, FireFox makes extensive use of Custom Memory Allocators"
echo "(CMAs) which results in spurious error messages."
echo

