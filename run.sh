#!/bin/bash

if [ x$1 != x ]
then
    sudo gcc -o output $1 -lpcap
    sudo ./output
else
    echo "no file"
fi
