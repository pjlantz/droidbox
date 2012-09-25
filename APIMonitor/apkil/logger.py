#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2012, The Honeynet Project. All rights reserved.
# Author: Kun Yang <kelwya@gmail.com>
#
# APKIL is free software: you can redistribute it and/or modify it under 
# the terms of version 3 of the GNU Lesser General Public License as 
# published by the Free Software Foundation.
#
# APKIL is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS 
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for 
# more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with APKIL.  If not, see <http://www.gnu.org/licenses/>.

import logging

debug = 'TERM'
debug = ""
log = None

def Pass(*args):
    pass

if debug == "TERM":
	logging.basicConfig(level=logging.DEBUG,
            format='%(filename)s Line:%(lineno)d Fun:%(funcName)s  %(message)s',)
	log = logging.debug
elif debug == "FILE":
	logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s Line:%(lineno)d Fun:%(funcName)s  %(message)s',
            filename='./apkil.log',
            filemode='w')
	log = logging.debug
else:
	log = Pass

