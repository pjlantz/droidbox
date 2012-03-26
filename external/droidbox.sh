#!/usr/bin/env bash

adb logcat -c | adb logcat dalvikvm:W *:S | python scripts/droidbox.py $1 $2
