#!/bin/bash

if [ x$1 != x ]
then
    sudo g++ -g -o output $1 -lpcap -lz
    sudo ./output
else
    echo "no file"
fi
