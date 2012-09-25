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

import sys
import os
import cPickle

from subprocess import check_output

class AndroidAPI(object):

    def __init__(self, level=None, jar_path=None):
        self.level = 0
        self.classes = {}

        if level and jar_path:
            self.read_jar(level, jar_path)

    def __repr__(self):
        return '\n'.join([repr(c) for c in self.classes])

    def show_classes(self):
        for c in self.classes.values():
            print "%s %s" % (" ".join(c.access), c.name)

    def show_not_API(self):
        for c in self.classes.values():
            if not c.isAPI:
                print "%s %s" % (" ".join(c.access), c.name)
                for m in c.methods.values():
                    print "    %s %s" % (" ".join(m.access), m.desc)

    def add_class(self, class_):
        if self.classes.has_key(class_.desc):
            return
        self.classes[class_.desc] = class_

    def read_jar(self, level, jar_path):
        self.level = level
        result = check_output(["jar", "-tf", jar_path])
        lines = result.split('\n')
        for line in lines:
            class_slash, ext = os.path.splitext(line)

            if ext != ".class":
                continue

            class_name = class_slash.replace('/', '.')
            result = check_output(["javap", "-bootclasspath", jar_path, "-s", class_name])
            class_lines = result.split('\n')
            segs = class_lines[1].replace('{', '').replace(", ", ',').split()
            c = AndroidClass()
            if "implements" in segs:
                k = segs.index("implements")
                c.implements = segs[-1].split(',')
                c.implements = ['L' + i.replace('.', '/') + ';' \
                                for i in c.implements]
                segs = segs[:k]
                """
                if len(c.implements) > 1:
                    print "*****"+class_lines[1]
                    sys.exit(0)
                """
            if "extends" in segs:
                c.name = segs[-3]
                c.supers = segs[-1].split(',')
                c.supers = ['L' + s.replace('.', '/') + ';' for s in c.supers]
                """
                if len(c.supers) > 1:
                    print "*****"+class_lines[1]
                    sys.exit(0)
                """
                c.access = segs[:-3]
            else:
                c.name = segs[-1]
                c.access = segs[:-1]
            print "[read] %s" % c.name
            c.desc = 'L' + c.name.replace('.', '/') + ';'

            i = 2
            while True:
                method_line = class_lines[i]
                method_line = method_line.replace(';', '')
                method_line = method_line.replace(', ', ',')
                if method_line[0] == '}': break
                m = AndroidMethod()
                segs = method_line.split()
                if "throws" in segs:
                    k = segs.index("throws")
                    m.throws = segs[-1].split(',')
                    """
                    if len(m.throws) > 1:
                        print class_lines[i]
                        sys.exit(0)
                    """
                    segs = segs[:k]
                segs[-1] = segs[-1][:segs[-1].find('(')]
                if segs[-1] == c.name:
                    m.name = "<init>"
                    m.access = segs[:-1]
                else:
                    m.name = segs[-1]
                    m.access = segs[:-2]

                i += 1
                method_line = class_lines[i]
                segs = method_line.split()
                m.desc = "%s->%s%s" % (c.desc, m.name, segs[-1])
                m.sdesc = m.desc[:m.desc.rfind(')') + 1]
                c.methods[m.sdesc]=m
                if not c.methods_by_name.has_key(m.name):
                    c.methods_by_name[m.name] = []
                c.methods_by_name[m.name].append(m.sdesc)
                i += 1

            self.classes[c.desc] = c
        self.build_connections()

    def build_connections(self, isAPI=True):
        for c in self.classes.values():
            if c.isAPI != isAPI:
                continue
            c.ancestors = []
            q = []
            q.extend(c.supers)
            while q:
                s = q.pop(0)
                if not s in c.ancestors:
                    c.ancestors.append(s)
                    if (not c.isAPI) and (not self.classes.has_key(s)):
                        continue
                    q.extend(self.classes[s].supers)
            #print "%s << %s " % (c.desc, \
            #        ",".join(c.ancestors))

    def save(self, data_path):
        f = open(data_path, 'w')
        #cPickle.dump(self, f)
        cPickle.dump((self.level, self.classes), f)
        f.close()
    
    def load(self, data_path):
        f = open(data_path, 'r')
        #self = cPickle.load(f)
        self.level, self.classes = cPickle.load(f)
        f.close

class AndroidClass(object):

    def __init__(self):
        self.name= ""
        self.supers = []
        self.ancestors = []
        self.access = []
        self.methods = {}
        self.methods_by_name = {}
        self.desc = ""
        self.implements = []
        self.isAPI = True

    def __repr__(self):
        """
        supers = ""
        if self.supers:
            supers = " extends " + " ".join(self.supers)
        implements = ""
        if self.implements:
            implements = " implements " + " ".join(self.implements)
        """
        return "%s %s%s%s" % (" ".join(self.access), self.desc, supers,
                implements)
        #return '\n'.join([repr(m) for m in self.methods])

class AndroidMethod(object):

    def __init__(self):
        self.name = ""
        self.class_ = None
        self.desc = ""
        self.sdesc = ""
        self.access = []
        self.throws = []
        self.type_ = ""
        self.isAPI = True

    def __repr__(self):
        return "%s %s" % (" ".join(self.access), self.desc)

