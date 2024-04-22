#!/bin/bash

set -x

[ -x ./kavsshvpn ] && rm ./kavsshvpn
MODE="-ggdb"
[ ! -z "$1" ] && [ "$1" == "prod" ] && MODE="-s -DPRODUCTION=1"

LIBSSH2=$(pkg-config libssh2 --cflags --libs)
[ $? != 0 ] && echo "Can't get info about libssh2" && exit 1

LIBS="$LIBSSH2"

gcc -Wall -pthread $MODE -pedantic kavsshvpn.c $LIBS -o kavsshvpn
