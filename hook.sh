#!/bin/sh

CMD=$@

LDPLFS_HOME=$HOME/myplfs

LD_PRELOAD="${LDPLFS_HOME}/libmyplfs.so ${PLFS_PATH-$HOME}/lib/libplfs.so ${PLFS_PATH-$HOME}/lib/libdl.so" $CMD
