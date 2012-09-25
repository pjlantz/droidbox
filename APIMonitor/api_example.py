#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import time
from androguard.core.bytecodes import apk
from apkil import smali, monitor, logger 
from subprocess import call

working_dir = sys.path[0]

APK = "examples/APKILTests.apk"
DEX = "examples/APKILTests.dex"
SMALI_DIR = "examples/APKILTests"

NEW_OUT = "examples/new"
NEW_DEX = "examples/classes.dex"
NEW_APK = "examples/new.apk"

a = apk.APK(APK)
min_version = int(a.get_min_sdk_version())
target_version = int(a.get_target_sdk_version())

dex_file = open(DEX, 'w')
dex_file.write(a.get_dex())
dex_file.close()

call(args=['java', '-jar', 'smali/baksmali.jar', '-b', '-o', SMALI_DIR, DEX])
s = smali.SmaliTree(min_version, SMALI_DIR)

db_path = os.path.join(working_dir, "androidlib")

API_LIST = [ \
"Landroid/net/Uri;->parse(Ljava/lang/String;)", \
"Landroid/content/Intent;-><init>(Ljava/lang/String;)", \
"Landroid/content/ContextWrapper;->openFileOutput(Ljava/lang/String;I)", \
"Ljava/io/OutputStreamWriter;->write(Ljava/lang/String;)", \
"Lapkil/tests/APKIL;->openFileInput(Ljava/lang/String;)",
"Ljava/io/BufferedReader;->readLine()Ljava/lang/String;", \
"Landroid/telephony/SmsManager;->sendTextMessage(\
Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;\
Landroid/app/PendingIntent;Landroid/app/PendingIntent;)", \
"Landroid/content/pm/PackageManager;->getInstalledApplications(I)",
]
mo = monitor.APIMonitor(db_path, API_LIST)

API_CONFIG = "config/default_api_collection"
mo = monitor.APIMonitor(db_path, config=API_CONFIG)

s = mo.inject(s, min_version)
s.save(NEW_OUT)

call(args=['java', '-jar', 'smali/smali.jar', '-a', str(min_version), '-o', NEW_DEX, NEW_OUT])

new_dex = open(NEW_DEX).read();
a.new_zip(filename=NEW_APK,
            deleted_files="(META-INF/.)", new_files = {
            "classes.dex" : new_dex } )
apk.sign_apk( NEW_APK, \
"config/apkil.cert", "apkil", "apkilapkil" )

