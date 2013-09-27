#!/bin/bash

if [ $# -lt 1 ] || [ $# -gt 2 ];then
	echo "Usage: $0 APK <duration in seconds>"
	exit 1;
fi

python "scripts/droidbox.py" $1 $2
