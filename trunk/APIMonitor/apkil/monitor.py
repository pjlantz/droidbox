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
import copy

from logger import log
from smali import ClassNode, MethodNode, FieldNode, InsnNode, \
                  TypeNode, LabelNode, TryNode, SmaliTree
from api import AndroidAPI, AndroidClass, AndroidMethod

PKG_PREFIX = "droidbox"
DEFAULT_HELPER = \
r'''
.class public Ldroidbox/apimonitor/Helper;
.super Ljava/lang/Object;
.method public constructor <init>()V
.registers 1
invoke-direct {p0}, Ljava/lang/Object;-><init>()V
return-void
.end method
.method public static log(Ljava/lang/String;)V
.registers 3
const-string v0, "\n"
const-string v1, "\\\\n"
invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
move-result-object p0
const-string v0, "\r"
const-string v1, "\\\\r"
invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
move-result-object p0
const-string v0, "DroidBox"
invoke-static {v0, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I
return-void
.end method
.method public static toString(Ljava/lang/Object;)Ljava/lang/String;
.registers 5
if-nez p0, :cond_5
const-string v3, "null"
:goto_4
return-object v3
:cond_5
invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
move-result-object v3
invoke-virtual {v3}, Ljava/lang/Class;->isArray()Z
move-result v3
if-eqz v3, :cond_3e
new-instance v2, Ljava/lang/StringBuilder;
const-string v3, "{"
invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
invoke-static {p0}, Ljava/lang/reflect/Array;->getLength(Ljava/lang/Object;)I
move-result v1
const/4 v0, 0x0
:goto_1b
if-lt v0, v1, :cond_27
const-string v3, "}"
invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
move-result-object v3
goto :goto_4
:cond_27
invoke-static {p0, v0}, Ljava/lang/reflect/Array;->get(Ljava/lang/Object;I)Ljava/lang/Object;
move-result-object v3
invoke-static {v3}, Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;
move-result-object v3
invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
add-int/lit8 v3, v1, -0x1
if-ge v0, v3, :cond_3b
const-string v3, ", "
invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
:cond_3b
add-int/lit8 v0, v0, 0x1
goto :goto_1b
:cond_3e
invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;
move-result-object v3
goto :goto_4
.end method
'''

METHOD_TYPE_BY_OPCODE = {
        "invoke-virtual": "instance",
        "invoke-super": "instance",
        "invoke-direct": "constructor",
        "invoke-static": "static",
        "invoke-interface": "instance",
        "invoke-virtual/range": "instance",
        "invoke-super/range": "instance",
        "invoke-direct/range": "constructor",
        "invoke-static/range": "static",
        "invoke-interface/range": "instance"
        }

OPCODE_MAP = {
        "invoke-virtual": "invoke-static",
        "invoke-super": "invoke-static",
        "invoke-direct": "invoke-static",
        "invoke-static": "invoke-static",
        "invoke-interface": "invoke-static",
        "invoke-virtual/range": "invoke-static/range",
        "invoke-super/range": "invoke-static/range",
        "invoke-direct/range": "invoke-static/range",
        "invoke-static/range": "invoke-static/range",
        "invoke-interface/range": "invoke-static/range"
        }

class APIMonitor(object):

    def __init__(self, db_dir, entries=[], config=""):
        self.db_dir = ""
        self.entries = []
        self.method_descs = [] 
        self.config = ""
        self.stub_classes = {}
        self.method_map = {}
        self.api_dict = {}
        self.api_name_dict = {}
        self.class_map = {}
        self.helper = ClassNode(buf=DEFAULT_HELPER)
        self.android_api = None 

        self.db_dir = db_dir
        self.entries = entries
        if (not entries) and config:
            if os.path.isfile(config):
                f = open(config, 'r')
                line = f.readline()
                while line:
                    if line.isspace():
                        line = f.readline()
                        continue
                    line = line.strip()
                    segs = line.split(None, 1)
                    if segs[0][0] == '#':
                        line = f.readline()
                        continue
                    if not line in self.entries:
                        self.entries.append(line)
                    line = f.readline()
                f.close()
            else:
                print "[error] Config file not found: %s" % config
                sys.exit(1)

    def __repr__(self):
        return '\n'.join(self.method_descs)
    
    def load_api(self, level):
        if level > 16:
            level = 16
        elif level < 3:
            level = 3
        self.android_api = AndroidAPI()
        data_path = os.path.join(self.db_dir, "android-%d.db" % level)
        while not os.path.exists(data_path):
            level += 1
            data_path = os.path.join(self.db_dir, "android-%d.db" % level)
        self.android_api.load(data_path)
        return level

    def inject(self, smali_tree, level):
        # get a copy of smali tree
        st = copy.deepcopy(smali_tree)

        # load api database
        print "Loading and processing API database..."
        level = self.load_api(level)
        print "Target API Level: %d" % level
        # check and fix apis in API_LIST
        method_descs = []
        for m in self.entries:
            c = ""
            api_name = ""
            method_name = ""

            ia = m.find("->")
            ilb = m.find('(')

            if ia >= 0:
                c = m[:ia]
                if ilb >= 0:
                    method_name = m[ia + 2:ilb]
                    api_name = m[ia + 2:]
                else:
                    method_name = m[ia + 2:]
            else:
                c = m

            if not self.android_api.classes.has_key(c):
                print "[Warn] Class not found in API-%d db: %s" % (level, m)
                continue
            # just class name
            if not method_name:
                ms = self.android_api.classes[c].methods.keys()
                method_descs.extend(ms)
            # full signature
            elif api_name:
                if not self.android_api.classes[c].methods.has_key(m):
                    if method_name == "<init>":
                        print "[Warn] Method not found in API-%d db: %s" % (level, m)
                        continue
                    c_obj = self.android_api.classes[c]
                    existed = False
                    q = c_obj.supers
                    while q:
                        cn = q.pop(0)
                        c_obj = self.android_api.classes[cn]
                        nm = c_obj.desc + "->" + api_name
                        if c_obj.methods.has_key(nm):
                            existed = True
                            if not nm in self.entries:
                                print "[Warn] Inferred API: %s" % (nm, )
                                method_descs.append(nm)
                        else:
                            q.extend(self.android_api.classes[cn].supers)

                    if not existed:
                        print "[Warn] Method not found in API-%d db: %s" % (level, m)
                else:
                    method_descs.append(m)
            # signature without parameters
            else:
                own = False
                if self.android_api.classes[c].methods_by_name.has_key(method_name):
                    ms = self.android_api.classes[c].methods_by_name[method_name]
                    method_descs.extend(ms)
                    own = True

                if method_name == "<init>":
                    continue
                c_obj = self.android_api.classes[c]
                existed = False
                q = c_obj.supers
                while q:
                    cn = q.pop(0)
                    c_obj = self.android_api.classes[cn]
                    if c_obj.methods_by_name.has_key(method_name):
                        existed = True
                        inferred = "%s->%s" % (c_obj.desc, method_name)
                        if not inferred in self.entries:
                            print "[Warn] Inferred API: %s" % inferred
                            method_descs.extend(c_obj.methods_by_name[method_name])
                    else:
                        q.extend(self.android_api.classes[cn].supers)

                if (not own) and (not existed):
                    print "[Warn] Method not found in API-%d db: %s" % (level, m)

        self.method_descs = list(set(method_descs))

        """ 
        print "**************************"
        self.method_descs.sort()
        print "\n".join(self.method_descs)
        print "**************************"
        """
        for m in self.method_descs:
            self.api_dict[m] = ""
            ia = m.find("->")
            ilb = m.find('(')
            if m[ia + 2:ilb] != "<init>":
                self.api_name_dict[m[ia + 2:]] = m[:ia]
        print "Done!"

        print "Injecting..."
        for c in st.classes:
            class_ = AndroidClass()
            class_.isAPI = False

            class_.desc = c.name
            class_.name= c.name[1:-1].replace('/', '.')
            class_.access = c.access
            if "interface" in c.access:
                class_.supers.extend(c.implements)
            else:
                class_.implements = c.implements
                class_.supers.append(c.super_name)

            for m in c.methods:
                method = AndroidMethod()
                method.isAPI = False
                method.desc = "%s->%s" % (c.name, m.descriptor)
                method.name = m.descriptor.split('(', 1)[0]
                #print method.desc
                method.sdesc = method.desc[:method.desc.rfind(')') + 1]
                method.access = m.access
                class_.methods[method.sdesc] = method 
            self.android_api.add_class(class_)
        self.android_api.build_connections(False)
        #self.android_api.show_not_API()

        for c in st.classes:
            for m in c.methods:
                i = 0
                while i < len(m.insns):
                    insn = m.insns[i]
                    if insn.fmt == "35c":
                        md = insn.obj.method_desc
                        on = insn.opcode_name
                        irb = md.find(')')
                        smd = md[:irb + 1]
                        if self.api_dict.has_key(smd):
                            method_type = METHOD_TYPE_BY_OPCODE[on]
                            new_on = OPCODE_MAP[on]
                            if not self.method_map.has_key(md):
                                self.add_stub_method(on, md)
                            if method_type == "constructor":
                                insn_m = copy.deepcopy(insn)
                                insn_m.obj.replace(new_on, \
                                        self.method_map[md])
                                r = insn_m.obj.registers.pop(0)
                                m.insert_insn(insn_m, i , 0)
                                i += 1
                                """
                                insn.obj.replace(new_on, \
                                        self.method_map[md])
                                r = insn.obj.registers.pop(0)
                                m.insert_insn(InsnNode(\
"move-result-object %s" % r), i + 1, 0)
                                i += 1
                                """
                            else:
                                insn.obj.replace(new_on, \
                                                 self.method_map[md])
                        else:
                            ia = md.find("->")
                            cn = md[:ia]
                            api_name = smd[ia + 2:]
                            if self.api_name_dict.has_key(api_name):
                                if self.android_api.classes.has_key(cn):
                                    if not self.android_api.classes[cn].methods.has_key(smd):
                                        api_cn = self.api_name_dict[api_name]
                                        if api_cn in self.android_api.classes[cn].ancestors:
                                            self.api_dict[smd] = ""
                                            i -= 1

                    elif insn.fmt == "3rc":
                        md = insn.obj.method_desc
                        on = insn.opcode_name
                        smd = md[:md.rfind(')') + 1]
                        if self.api_dict.has_key(smd):
                            method_type = METHOD_TYPE_BY_OPCODE[on]
                            new_on = OPCODE_MAP[on]
                            if not self.method_map.has_key(md):
                                self.add_stub_method(on, md)
                            if method_type == "constructor":
                                insn_m = copy.deepcopy(insn)
                                insn_m.obj.replace(new_on, \
                                        self.method_map[md])
                                r = insn_m.obj.reg_start
                                nr = r[0] + str(int(r[1:]) + 1)
                                insn_m.obj.set_reg_start(nr)
                                m.insert_insn(insn_m, i , 0)
                                i += 1
                                """
                                insn.obj.replace(new_on, \
                                        self.method_map[md])
                                r = insn.obj.reg_start
                                nr = r[0] + str(int(r[1:]) + 1)
                                insn.obj.set_reg_start(nr)
                                m.insert_insn(InsnNode(\
"move-result-object %s" % r), i + 1, 0)
                                i += 1
                                """
                            else:
                                insn.obj.replace(new_on, \
                                                 self.method_map[md])
                        else:
                            ia = md.find("->")
                            cn = md[:ia]
                            api_name = smd[ia + 2:]
                            if self.api_name_dict.has_key(api_name):
                                if self.android_api.classes.has_key(cn):
                                    if not self.android_api.classes[cn].methods.has_key(smd):
                                        api_cn = self.api_name_dict[api_name]
                                        if api_cn in self.android_api.classes[cn].ancestors:
                                            self.api_dict[smd] = ""
                                            i -= 1
                    i += 1

        for c in self.stub_classes.values():
            st.add_class(c)

        st.add_class(self.helper)
        print "Done!"

        return st

    def add_stub_method(self, on, m):
        #segs = m.split(':', 1)
        #method_type = segs[0]
        #m = segs[1]
        method_type = METHOD_TYPE_BY_OPCODE[on]
        segs = m.rsplit("->", 1)

        if self.stub_classes.has_key(segs[0]):
            stub_class = self.stub_classes[segs[0]]
        else:
            stub_class = ClassNode()
            stub_class.set_name("L" + PKG_PREFIX + "/" + segs[0][1:])
            stub_class.add_access("public")
            stub_class.set_super_name("Ljava/lang/Object;")

            self.stub_classes[segs[0]] = stub_class
            self.class_map[segs[0]] = "L" + PKG_PREFIX + "/" + segs[0][1:]

            #.method public constructor <init>()V
            #    .registers 1
            #    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
            #    return-void
            #.end method
            method = MethodNode()
            method.set_desc("<init>()V")
            method.add_access(["public", "constructor"])
            method.set_registers(1)
            i1 = InsnNode("invoke-direct {p0}, Ljava/lang/Object;-><init>()V")
            i2 = InsnNode("return-void")
            method.add_insn([i1, i2])
            stub_class.add_method(method)

        method_name = segs[1][:segs[1].find("(")]
        if method_type == "constructor":
            self.__add_stub_cons2(stub_class, m)
        elif method_type == "instance":
            self.__add_stub_inst(stub_class, on, m)
        elif method_type == "static":
            self.__add_stub_static(stub_class, m)


    def __add_stub_inst(self, stub_class, on, m):
        segs = m.rsplit("->", 1)

        method = MethodNode()
        method.set_desc(segs[1])
        method.add_para(TypeNode(segs[0]))
        method.add_access(["public", "static"])

        para_num = len(method.paras)
        reg_num = method.get_paras_reg_num()
        ri = 1

        if reg_num <= 5:
            if on.find('/') >= 0:
                on = on[:on.find('/')]
            i = "%s {%s}, %s" % \
                    (on, \
                     ", ".join(["p%d" % k for k in range(reg_num)]), m)
        else:
            i = "%s {p0 .. p%d}, %s" % (on, reg_num - 1, m) 

        method.add_insn(InsnNode(i)) 

        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("move-result v1"))
                    ri += 1
                else:
                    method.add_insn(InsnNode("move-result-wide v1"))
                    ri += 2
            else:
                method.add_insn(InsnNode("move-result-object v1"))
                ri += 1

        method.add_insn(InsnNode("new-instance \
v%d, Ljava/lang/StringBuilder;" % ri))
        method.add_insn(InsnNode("invoke-direct \
{v%d}, Ljava/lang/StringBuilder;-><init>()V" % ri))

        method.add_insn(InsnNode("const-string v%d,\"%s(\"" % \
                                 (ri + 1, m.split('(', 1)[0])))
        append_i = InsnNode("invoke-virtual \
{v%d, v%d}, Ljava/lang/StringBuilder;->\
append(Ljava/lang/String;)Ljava/lang/StringBuilder;" % \
                            (ri, ri + 1))
        method.add_insn(append_i)
        
        # print parameters
        pi = 1
        for k in range(1, para_num):
            p = method.paras[k]
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)

            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {p%d}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             (pi, p.get_desc())))
                    pi += 1
                else:
                    method.add_insn(InsnNode("invoke-static \
{p%d, p%d}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                        (pi, pi + 1, p.get_desc())))
                    pi += 2
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {p%d}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;" % (pi, )))
                pi += 1
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

            if k < para_num - 1:
                method.add_insn(InsnNode("const-string v%d, \" | \"" % \
                                         (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("const-string v%d, \")\"" % (ri + 1)))
        method.add_insn(append_i)

        # print return value
        p = method.ret
        if p.void:
            method.add_insn(InsnNode("const-string v%d, \"%s\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
        else:
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {v1}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                else:
                    method.add_insn(InsnNode("invoke-static \
{v1, v2}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {v1}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;"))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("invoke-virtual {v%d}, \
Ljava/lang/StringBuilder;->toString()Ljava/lang/String;" % ri))
        method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
        method.add_insn(InsnNode("invoke-static {v%d}, \
Ldroidbox/apimonitor/Helper;->log(Ljava/lang/String;)V" % \
                                 (ri + 1, )))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("return v1"))
                else:
                    method.add_insn(InsnNode("return-wide v1"))
            else:
                method.add_insn(InsnNode("return-object v1"))
        else:
            method.add_insn(InsnNode("return-void"))

        start = LabelNode(":droidbox_try_start", 0)
        end = LabelNode(":droidbox_try_end", 1)
        index = len(method.insns)
        ret = LabelNode(":droidbox_return", index - 1)
        handler = LabelNode(":droidbox_handler", index)
        line = ".catch Ljava/lang/Exception; {:droidbox_try_start .. \
:droidbox_try_end} :droidbox_handler"
        TryNode(line, start, end, handler)
        method.add_label([start, end, ret, handler])

        method.add_insn(InsnNode("move-exception v0"))
        method.add_insn(InsnNode("invoke-virtual {v0}, \
Ljava/lang/Exception;->printStackTrace()V"))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("const/4 v1, 0x0"))
                else:
                    method.add_insn(InsnNode("const-wide/16 v1, 0x0"))
            else:
                method.add_insn(InsnNode("const/4 v1, 0x0"))
        method.add_insn(InsnNode("goto :droidbox_return"))

        method.set_registers(reg_num + ri + 2)
        stub_class.add_method(method)

        i = m.find('(')
        self.method_map[m] = "L" + PKG_PREFIX + "/" + segs[0][1:] + "->" + \
                method.get_desc()


    def __add_stub_cons2(self, stub_class, m):
        segs = m.rsplit("->", 1)
        desc = segs[1].replace("<init>", "droidbox_cons")
        i = desc.find(')')
        desc = desc[:i + 1] + 'V'
        method = MethodNode()
        method.set_desc(desc)
        method.add_access(["public", "static"])

        para_num = len(method.paras)
        reg_num = method.get_paras_reg_num()
        ri = 0

        method.add_insn(InsnNode("new-instance \
v%d, Ljava/lang/StringBuilder;" % ri))
        method.add_insn(InsnNode("invoke-direct \
{v%d}, Ljava/lang/StringBuilder;-><init>()V" % ri))

        method.add_insn(InsnNode("const-string v%d,\"%s(\"" % \
                                 (ri + 1, m.split('(', 1)[0])))
        append_i = InsnNode("invoke-virtual \
{v%d, v%d}, Ljava/lang/StringBuilder;->\
append(Ljava/lang/String;)Ljava/lang/StringBuilder;" % \
                            (ri, ri + 1))
        method.add_insn(append_i)
        
        # print parameters
        pi = 0
        for k in range(0, para_num):
            p = method.paras[k]
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)

            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {p%d}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             (pi, p.get_desc())))
                    pi += 1
                else:
                    method.add_insn(InsnNode("invoke-static \
{p%d, p%d}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                        (pi, pi + 1, p.get_desc())))
                    pi += 2
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {p%d}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;" % (pi, )))
                pi += 1
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

            if k < para_num - 1:
                method.add_insn(InsnNode("const-string v%d, \" | \"" % \
                                         (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("const-string v%d, \")\"" % (ri + 1)))
        method.add_insn(append_i)

        # print return value
        p = method.ret
        if p.void:
            method.add_insn(InsnNode("const-string v%d, \"%s\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
        else:
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {v1}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                else:
                    method.add_insn(InsnNode("invoke-static \
{v1, v2}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {v1}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;"))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("invoke-virtual {v%d}, \
Ljava/lang/StringBuilder;->toString()Ljava/lang/String;" % ri))
        method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
        method.add_insn(InsnNode("invoke-static {v%d}, \
Ldroidbox/apimonitor/Helper;->log(Ljava/lang/String;)V" % \
                                 (ri + 1, )))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("return v1"))
                else:
                    method.add_insn(InsnNode("return-wide v1"))
            else:
                method.add_insn(InsnNode("return-object v1"))
        else:
            method.add_insn(InsnNode("return-void"))

        method.set_registers(reg_num + ri + 2)
        stub_class.add_method(method)

        i = m.find('(')
        self.method_map[m] = "L" + PKG_PREFIX + "/" + segs[0][1:] + "->" + \
                method.get_desc()

    def __add_stub_cons(self, stub_class, m):
        segs = m.rsplit("->", 1)
        desc = segs[1].replace("<init>", "droidbox_cons")
        i = desc.find(')')
        desc = desc[:i + 1] + segs[0]
        method = MethodNode()
        method.set_desc(desc)
        method.add_access(["public", "static"])

        para_num = len(method.paras)
        reg_num = method.get_paras_reg_num()
        ri = 1

        method.add_insn(InsnNode("new-instance v1, %s" % segs[0]))

        reg_v = 1
        if reg_num <= 4:
            i = "invoke-direct {v1, %s}, %s" % \
                    (", ".join(["p%d" % k for k in range(reg_num)]), \
                     m)
            method.add_insn(InsnNode(i)) 
        else:
            for k in range(reg_num):
                method.add_insn(InsnNode("move-object v%d, p%d" % (k + 2, k)))
            i = "invoke-direct/range {v1 .. v%d}, %s" % \
                    (reg_num + 1, m)
            method.add_insn(InsnNode(i)) 
            reg_v = reg_num + 1

        ri += 1

        method.add_insn(InsnNode("new-instance \
v%d, Ljava/lang/StringBuilder;" % ri))
        method.add_insn(InsnNode("invoke-direct \
{v%d}, Ljava/lang/StringBuilder;-><init>()V" % ri))

        method.add_insn(InsnNode("const-string v%d,\"%s(\"" % \
                                 (ri + 1, m.split('(', 1)[0])))
        append_i = InsnNode("invoke-virtual \
{v%d, v%d}, Ljava/lang/StringBuilder;->\
append(Ljava/lang/String;)Ljava/lang/StringBuilder;" % \
                            (ri, ri + 1))
        method.add_insn(append_i)
        
        # print parameters
        pi = 0
        for k in range(0, para_num):
            p = method.paras[k]
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)

            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {p%d}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             (pi, p.get_desc())))
                    pi += 1
                else:
                    method.add_insn(InsnNode("invoke-static \
{p%d, p%d}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                        (pi, pi + 1, p.get_desc())))
                    pi += 2
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {p%d}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;" % (pi, )))
                pi += 1
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

            if k < para_num - 1:
                method.add_insn(InsnNode("const-string v%d, \" | \"" % \
                                         (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("const-string v%d, \")\"" % (ri + 1)))
        method.add_insn(append_i)

        # print return value
        p = method.ret
        if p.void:
            method.add_insn(InsnNode("const-string v%d, \"%s\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
        else:
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {v1}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                else:
                    method.add_insn(InsnNode("invoke-static \
{v1, v2}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {v1}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;"))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("invoke-virtual {v%d}, \
Ljava/lang/StringBuilder;->toString()Ljava/lang/String;" % ri))
        method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
        method.add_insn(InsnNode("invoke-static {v%d}, \
Ldroidbox/apimonitor/Helper;->log(Ljava/lang/String;)V" % \
                                 (ri + 1, )))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("return v1"))
                else:
                    method.add_insn(InsnNode("return-wide v1"))
            else:
                method.add_insn(InsnNode("return-object v1"))
        else:
            method.add_insn(InsnNode("return-void"))

        start = LabelNode(":droidbox_try_start", 0)
        end = LabelNode(":droidbox_try_end", 2)
        index = len(method.insns)
        ret = LabelNode(":droidbox_return", index - 1)
        handler = LabelNode(":droidbox_handler", index)
        line = ".catch Ljava/lang/Exception; {:droidbox_try_start .. \
:droidbox_try_end} :droidbox_handler"
        TryNode(line, start, end, handler)
        method.add_label([start, end, ret, handler])

        method.add_insn(InsnNode("move-exception v0"))
        method.add_insn(InsnNode("invoke-virtual {v0}, \
Ljava/lang/Exception;->printStackTrace()V"))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("const/4 v1, 0x0"))
                else:
                    method.add_insn(InsnNode("const-wide/16 v1, 0x0"))
            else:
                method.add_insn(InsnNode("const/4 v1, 0x0"))
        method.add_insn(InsnNode("goto :droidbox_return"))

        method.set_registers(reg_num + max(ri + 1, reg_v) + 1)
        stub_class.add_method(method)

        i = m.find('(')
        self.method_map[m] = "L" + PKG_PREFIX + "/" + segs[0][1:] + "->" + \
                method.get_desc()

#invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    def __add_stub_static(self, stub_class, m):
        segs = m.rsplit("->", 1)

        method = MethodNode()
        method.set_desc(segs[1])
        method.add_access(["public", "static"])

        para_num = len(method.paras)
        reg_num = method.get_paras_reg_num()
        ri = 1

        if reg_num <= 5:
            i = "invoke-static {%s}, %s" % \
                    (", ".join(["p%d" % k for k in range(reg_num)]), m)
        else:
            i = "invoke-static/range {p0 .. p%d}, %s" % (reg_num - 1, m) 

        method.add_insn(InsnNode(i)) 

        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("move-result v1"))
                    ri += 1
                else:
                    method.add_insn(InsnNode("move-result-wide v1"))
                    ri += 2
            else:
                method.add_insn(InsnNode("move-result-object v1"))
                ri += 1

        method.add_insn(InsnNode("new-instance \
v%d, Ljava/lang/StringBuilder;" % ri))
        method.add_insn(InsnNode("invoke-direct \
{v%d}, Ljava/lang/StringBuilder;-><init>()V" % ri))

        method.add_insn(InsnNode("const-string v%d,\"%s(\"" % \
                                 (ri + 1, m.split('(', 1)[0])))
        append_i = InsnNode("invoke-virtual \
{v%d, v%d}, Ljava/lang/StringBuilder;->\
append(Ljava/lang/String;)Ljava/lang/StringBuilder;" % \
                            (ri, ri + 1))
        method.add_insn(append_i)
        
        # print parameters
        pi = 0
        for k in range(0, para_num):
            p = method.paras[k]
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)

            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {p%d}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             (pi, p.get_desc())))
                    pi += 1
                else:
                    method.add_insn(InsnNode("invoke-static \
{p%d, p%d}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                        (pi, pi + 1, p.get_desc())))
                    pi += 2
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {p%d}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;" % (pi, )))
                pi += 1
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

            if k < para_num - 1:
                method.add_insn(InsnNode("const-string v%d, \" | \"" % \
                                         (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("const-string v%d, \")\"" % (ri + 1)))
        method.add_insn(append_i)

        # print return value
        p = method.ret
        if p.void:
            method.add_insn(InsnNode("const-string v%d, \"%s\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
        else:
            method.add_insn(InsnNode("const-string v%d, \"%s=\"" % (ri + 1,
                                     p.get_desc())))
            method.add_insn(append_i)
            if p.basic and p.dim == 0:
                if p.words == 1:
                    method.add_insn(InsnNode("invoke-static {v1}, \
Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                else:
                    method.add_insn(InsnNode("invoke-static \
{v1, v2}, Ljava/lang/String;->valueOf(%s)Ljava/lang/String;" % \
                                             p.get_desc()))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)
            else:
                method.add_insn(InsnNode("invoke-static {v1}, \
Ldroidbox/apimonitor/Helper;->toString(Ljava/lang/Object;)Ljava/lang/String;"))
                method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
                method.add_insn(append_i)

        method.add_insn(InsnNode("invoke-virtual {v%d}, \
Ljava/lang/StringBuilder;->toString()Ljava/lang/String;" % ri))
        method.add_insn(InsnNode("move-result-object v%d" % (ri + 1)))
        method.add_insn(InsnNode("invoke-static {v%d}, \
Ldroidbox/apimonitor/Helper;->log(Ljava/lang/String;)V" % \
                                 (ri + 1, )))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("return v1"))
                else:
                    method.add_insn(InsnNode("return-wide v1"))
            else:
                method.add_insn(InsnNode("return-object v1"))
        else:
            method.add_insn(InsnNode("return-void"))

        start = LabelNode(":droidbox_try_start", 0)
        end = LabelNode(":droidbox_try_end", 1)
        index = len(method.insns)
        ret = LabelNode(":droidbox_return", index - 1)
        handler = LabelNode(":droidbox_handler", index)
        line = ".catch Ljava/lang/Exception; {:droidbox_try_start .. \
:droidbox_try_end} :droidbox_handler"
        TryNode(line, start, end, handler)
        method.add_label([start, end, ret, handler])

        method.add_insn(InsnNode("move-exception v0"))
        method.add_insn(InsnNode("invoke-virtual {v0}, \
Ljava/lang/Exception;->printStackTrace()V"))
        if not method.ret.void:
            if method.ret.basic and method.ret.dim == 0:
                if method.ret.words == 1:
                    method.add_insn(InsnNode("const/4 v1, 0x0"))
                else:
                    method.add_insn(InsnNode("const-wide/16 v1, 0x0"))
            else:
                method.add_insn(InsnNode("const/4 v1, 0x0"))
        method.add_insn(InsnNode("goto :droidbox_return"))

        method.set_registers(reg_num + ri + 2)
        stub_class.add_method(method)

        i = m.find('(')
        self.method_map[m] = "L" + PKG_PREFIX + "/" + segs[0][1:] + "->" + \
                method.get_desc()



