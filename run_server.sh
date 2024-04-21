#!/bin/bash

P="./kavsshvpn"
[ ! -x "$P" ] && echo "Can't found $P" && exit 1

#VG="valgrind"
#VG="gdb -ex=r --args"
VG=""

sudo $VG $P -s \
	-H 145.32.166.10 \
	-P 22 \
	-n 10.254.254.0 \
	-a /home/user/.ssh/id_rsa.pub \
	-b /home/user/.ssh/id_rsa \
	-x "secretkeypass"
