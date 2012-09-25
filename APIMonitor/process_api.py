#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
from apkil import api
import cPickle

levels = [3, 4, 7, 8, 10, 11, 12, 13, 14, 15,16]

for level in levels:

    jar_name = "android-%d.jar" % level
    jar_path = os.path.join("androidlib", jar_name)
    data_path = os.path.join("androidlib", "android-%d.db" % level)

    android_api = api.AndroidAPI(level, jar_path)
    android_api.save(data_path)


