#!/bin/sh

# this script is just for personal use, for instructions on how to build see README.md

# debug build with sanitizers and debug printing enabled
CC=clang meson setup build --buildtype=debug -Db_sanitize=address,undefined -Dc_args="$CFLAGS -DENABLE_DEBUG_PRINT"

# release build
# CC=clang meson setup build --buildtype=release
