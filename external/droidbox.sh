#!/usr/bin/env bash

adb logcat -c | adb logcat dalvikvm:W *:S | scripts/droidbox.py $1
