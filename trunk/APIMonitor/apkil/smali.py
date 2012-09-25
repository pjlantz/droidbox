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

import os
import copy
import sys
import shutil
import StringIO

from logger import log

INSN_FMT = {
        "invoke-virtual": "35c",
        "invoke-super": "35c",
        "invoke-direct": "35c",
        "invoke-static": "35c",
        "invoke-interface": "35c",
        "invoke-virtual/range": "3rc",
        "invoke-super/range": "3rc",
        "invoke-direct/range": "3rc",
        "invoke-static/range": "3rc",
        "invoke-interface/range": "3rc"
        }

BASIC_TYPES = {
        'V': "void",
        'Z': "boolean",
        'B': "byte",
        'S': 'short',
        'C': "char",
        'I': "int",
        'J': "long",
        'F': "float",
        'D': "double"
        }

BASIC_TYPES_BY_JAVA = {
        "void": 'V',
        "boolean": 'Z',
        "byte": 'B',
        'short': 'S',
        "char": 'C',
        "int": 'I',
        "long": 'J',
        "float": 'F',
        "double": 'D'
        }

class SmaliTree(object):

    def __init__(self, level, foldername):
        self.foldername = ""
        self.smali_files = []
        self.classes = []
        self.level = level

        self.__parse(foldername)

    def __repr__(self):
        return "Foldername: %s\n%s" % \
                (self.foldername, \
                "".join([repr(class_) for class_ in self.classes]))

    def __parse(self, foldername):
        print "Parsing %s..." % foldername
        self.foldername = foldername
        for (path, dirs, files) in os.walk(self.foldername):
            for f in files:
                name = os.path.join(path, f)
                rel = os.path.relpath(name, self.foldername)
                if rel.find("annotation") == 0:
                    continue
                ext = os.path.splitext(name)[1]
                if ext != '.smali': continue
                self.smali_files.append(name)
                self.classes.append(ClassNode(name))
        # print repr(self.smali_files)
        log("SmaliTree parsed!")
        print "Done!"

    def get_class(self, class_name):
        result = [c for c in self.classes if c.name == class_name]
        if result:
            return result[0]
        else:
            return None
    
    def add_class(self, class_node):
        if [c for c in self.classes if c.name == class_node.name]:
            print "Class %s alreasy exsits!" % class_node.name
            return False
        else:
            self.classes.append(copy.deepcopy(class_node))
            return True

    def remove_class(self, class_node):
        # self.classes.del()
        pass

    def save(self, new_foldername):
        print "Saving %s..." % new_foldername
        if os.path.exists(new_foldername):
            shutil.rmtree(new_foldername)
        os.makedirs(new_foldername)
        for c in self.classes:
            c.save(new_foldername)
        print "Done"

    def export_apk(self):
        self.save("./out")
    

class ClassNode(object):

    def __init__(self, filename=None, buf=None):
        self.buf = []
        self.filename = "" 
        self.name = ''
        self.super_name= ''
        self.source = ''
        self.implements = []
        self.access = []
        self.interfaces = []
        self.fields = []
        self.methods = []
        self.inner_classes = []
        self.annotations = []
        self.debugs = []

        if filename or buf:
            self.__parse(filename, buf)

    def __repr__(self):
        return  "Class: %s %s << %s\n%s%s" % \
                (' '.join(self.access), self.name, self.super_name, \
                ''.join([repr(f) for f in self.fields]), \
                ''.join([repr(m) for m in self.methods]))

    def __parse(self, filename, buf):
        if filename:
            self.filename = filename
            f = open(self.filename, 'r')
        elif buf:
            f = StringIO.StringIO(buf)
        else:
            return

        line = f.readline()
        while line:
            if line.isspace():
                line = f.readline()
                continue
            line = line.strip()
            segs = line.split()
            # .source <source-file>
            if segs[0] == ".source":
                self.source = segs[1]
            # .class <access-spec> <class-name>
            elif segs[0] == ".class":
                self.name = segs[-1]
                # <access-spec>: public, final, super, interface, abstract
                self.access = segs[1:-1]
            # .super <class-name>
            elif segs[0] == ".super":
                self.super_name = segs[1]
            elif segs[0] == ".interface":
                print "can't parse .interface"
                sys.exit(1)
            elif segs[0] == ".implements":
                self.implements.append(segs[1])
            elif segs[0] == ".field":
                self.fields.append(FieldNode(line))
            elif segs[0] == ".method":
                lines = [line]
                line = f.readline()
                while line:
                    if line.isspace():
                        line = f.readline()
                        continue
                    line = line.strip()
                    lines.append(line)
                    segs = line.split(None, 2)
                    if segs[0] == ".end" and segs[1] == "method":
                        break
                    line = f.readline()
                self.methods.append(MethodNode(lines))
            elif segs[0] == ".annotation":
                # there may be subannotations
                lines = [line]
                line = f.readline()
                while line:
                    if line.isspace():
                        line = f.readline()
                        continue
                    line = line.strip()
                    lines.append(line)
                    segs = line.split(None, 2)
                    if segs[0] == ".end" and segs[1] == "annotation":
                        break
                    line = f.readline()
                #self.annotations
            elif segs[0] == '#':
                pass
            line = f.readline()
        f.close()
        log("ClassNode: " + self.name + " parsed!")

    def reload(self):
        self.buf = []
        # .class
        self.buf.append(".class %s %s" % (' '.join(self.access), self.name))
        # .super
        self.buf.append(".super %s" % (self.super_name, ))
        # .source
        if self.source:
            self.buf.append(".source %s" % (self.source, ))
        # .implements
        if self.implements:
            for imp in self.implements:
                self.buf.append(".implements %s" % (imp, ))
        # .interfaces 
        # .field
        for f in self.fields:
            f.reload()
            self.buf.append(f.buf)
        # .method
        for m in self.methods:
            m.reload()
            self.buf.extend(m.buf)

    def set_name(self, name):
        self.name = name
    
    def add_access(self, access):
        if type(access) == list:
            self.access.extend(access)
        else:
            self.access.append(access)

    def set_super_name(self, super_name):
        self.super_name = super_name
    
    def add_field(self, field):
        self.fields.append(field)

    def add_method(self, method):
        if type(method) == list:
            self.methods.extend(method)
        else:
            self.methods.append(method)

    def save(self, new_foldername):
        self.reload()
        path, filename = os.path.split(self.name[1:-1])
        filename += ".smali"
        path = os.path.join(new_foldername, path)
        if not os.path.exists(path):
            os.makedirs(path)
        filename = os.path.join(path, filename)
        f = open(filename, 'w')
        f.write('\n'.join(self.buf))
        f.close()


class FieldNode(object):

    def __init__(self, line=None):
        self.buf = ""
        self.name = ""
        self.access = []
        self.descriptor = ""
        self.value = None

        if line:
            self.__parse(line)

    def __repr__(self):
        return "    Field: %s %s %s%s\n" % \
                (' '.join(self.access), self.descriptor, self.name, \
                self.value and "=" + self.value or "")

    # .field <access-spec> <field-name>:<descriptor> [ = <value> ]
    def __parse(self, line):
        #log("FieldNode: " + line + " parsing")
        self.buf = line
        i = self.buf.find('=')
        segs = []
        if i > 0:
            segs = self.buf[:i].split()
            self.value = self.buf[i + 1:].strip()
        else:
            segs = self.buf.split()
        self.access = segs[1:-1]
        self.name, self.descriptor = segs[-1].split(':')
        log("FieldNode: " + self.name + " parsed!")

    def set_name(self, name):
        self.name = name

    def add_access(self, access):
        if type(access) == list:
            self.access.extend(access)
        else:
            self.access.append(access)

    def set_desc(self, desc):
        self.descriptor = desc

    def set_value(self, value):
        self.value = value
    
    def reload(self):
        self.buf = "%s %s %s:%s" % \
                (".field", ' '.join(self.access), self.name, \
                self.descriptor)
        if self.value: self.buf += " = %s" % self.value

class MethodNode(object):

    def __init__(self, lines=None):
        self.name = ""
        self.buf = []
        self.access = []
        self.descriptor = ""
        self.paras = []
        self.ret = ""
        self.registers = 0
        self.insns = []
        self.labels = {}
        self.tries = []
        self.is_constructor = False

        if lines:
            self.__parse(lines)


    def __repr__(self):
        return "    Method: %s %s\n        registers: %d\n%s" % \
                (' '.join(self.access), self.descriptor, self.registers, \
                ''.join(["%13d %s" % \
                (self.insns.index(i), repr(i)) for i in self.insns]))

    # .method <access-spec> <method-spec>
    #     <statements>
    # .end method
    def __parse(self, lines):
        self.buf = lines
        segs = self.buf[0].split()
        self.access = segs[1:-1]
        self.descriptor = segs[-1]
        self.name = self.descriptor.split('(', 1)[0]
        self.__parse_desc()

        start = 1
        # .registers <register-num>
        segs = self.buf[1].split()
        if segs[0] == ".registers":
            self.registers = int(segs[1])
            start = 2

        index = 0
        try_node_cache = []
        k = start
        while k < len(self.buf) - 1:
            line = self.buf[k]
            segs = line.split()
            # :<label-name>
            if segs[0][0] == ":":
                label = LabelNode(line, index)
                self.labels[label.name] = label
            # .catch <classname> {<label1> .. <label2>} <label3>
            # .catchall {<label1> .. <label2>} <label3>
            elif segs[0] == ".catch" or segs[0] == ".catchall": 
                try_node_cache.append(line)
            elif segs[0] == ".packed-switch" or segs[0] == ".sparse-switch":
                lb = self.labels[self.buf[k - 1][1:]]
                lines = [line]
                k += 1
                line = self.buf[k]
                lines.append(line)
                segs = line.split()
                while segs[0] != ".end":
                    k += 1
                    line = self.buf[k]
                    lines.append(line)
                    segs = line.split()
                SwitchNode(lines, lb)
            elif segs[0] == ".array-data":
                lb = self.labels[self.buf[k - 1][1:]]
                lines = [line]
                k += 1
                line = self.buf[k]
                lines.append(line)
                segs = line.split()
                while segs[0] != ".end":
                    k += 1
                    line = self.buf[k]
                    lines.append(line)
                    segs = line.split()
                ArrayDataNode(lines, lb)
            elif segs[0] == ".annotation":
                k += 1
                lines = [line]
                line = self.buf[k]
                lines.append(line)
                segs = line.split()
                while (segs[0] != ".end" or segs[1] != "annotation"):
                    k += 1
                    line = self.buf[k]
                    lines.append(line)
                    segs = line.split()
                # parse lines
            else:
                self.insns.append(InsnNode(line))
                index += 1
            k += 1

        for line in try_node_cache:
            segs = line.split()
            start = self.labels[segs[-4][2:]]
            end = self.labels[segs[-2][1:-1]]
            handler = self.labels[segs[-1][1:]]
            self.tries.append(TryNode(line, start, end, handler))
        try_node_cache = []

        if self.name == "<init>":
            self.is_constructor = True
        log("MethodNode: " + self.name + " parsed!")

    def __parse_desc(self):
        self.name = self.descriptor.split('(', 1)[0]
        p1 = self.descriptor.find('(')
        p2 = self.descriptor.find(')')
        self.ret = TypeNode(self.descriptor[p2 + 1:])
        self.paras = []
        paras = self.descriptor[p1 + 1:p2]
        index = 0
        dim = 0
        while index < len(paras):
            c = paras[index]
            if c == '[':
                dim += 1
                index += 1
            elif BASIC_TYPES.has_key(c):
                self.paras.append(TypeNode(paras[index - dim:index + 1]))
                index += 1
                dim = 0
            else:
                tmp = paras.find(';', index)
                self.paras.append(TypeNode(paras[index - dim:tmp + 1]))
                index = tmp + 1
                dim = 0

    def reload(self):
        self.__parse_desc()

        self.buf = []
        for i in self.insns:
            i.reload()
            self.buf.append(i.buf)
        # insert labels and tries
        # sort the labels by index
        count = 0
        labels = self.labels.values()
        from operator import attrgetter
        labels = sorted(labels, key=attrgetter('index'))
        for l in labels:
            self.buf.insert(l.index + count, l.buf)
            count += 1
            for t in l.tries:
                self.buf.insert(l.index + count, t.buf)
                count += 1
            if l.switch:
                for sl in l.switch.buf:
                    self.buf.insert(l.index + count, sl)
                    count += 1
            if l.array_data:
                for sl in l.array_data.buf:
                    self.buf.insert(l.index + count, sl)
                    count += 1

        if self.registers > 0:
            self.buf.insert(0, ".registers %d" % self.registers)
        elif (not "abstract" in self.access) and \
                (not "final" in self.access) and \
                (not "native" in self.access):
            self.buf.insert(0, ".registers 0")
        self.buf.insert(0, ".method %s %s" % \
                (' '.join(self.access), self.descriptor))
        self.buf.append(".end method")

    def get_insn_by_index(self, index):
        if index < 0 or index >= len(self.insns): return None
        return self.insns[index]

    def get_insn35c(self, opcode_name, method_desc):
        result = []
        for i in self.insns:
            if i.fmt == "35c" and i.opcode_name == opcode_name and \
                    i.obj.method_desc == method_desc:
                result.append(i)
        return result

    def get_desc(self):
        return self.descriptor

    def get_paras_reg_num(self):
        reg_num = 0
        for p in self.paras:
            reg_num += p.words
        return reg_num

    def set_name(self, name):
        self.name = name

    def set_desc(self, desc):
        self.descriptor = desc
        self.__parse_desc()

    def add_para(self, para, index=0):
        self.paras.insert(index, para)
        self.descriptor = self.name + '('
        for p in self.paras:
            self.descriptor += p.get_desc()
        self.descriptor += ')'
        self.descriptor += self.ret.get_desc()

    def insert_insn(self, insn, index=0, direction=0):
        self.insns.insert(index, insn)
        for l in self.labels.values():
            if l.index >= index + direction:
                l.index += 1

    def add_access(self, access):
        if type(access) == list:
            self.access.extend(access)
        else:
            self.access.append(access)

    def add_label(self, label):
        if type(label) == list:
            for l in label:
                self.labels[l.name] = l
        else:
            self.labels[label.name] = label

    def set_registers(self, registers):
        self.registers = registers

    def add_insn(self, insn):
        if type(insn) == list:
            self.insns.extend(insn)
        else:
            self.insns.append(insn)

    def replace_insn35c(self):
        for i in self.insns:
            i.replace()
    

class InsnNode(object):

    def __init__(self, line=None):
        self.buf = ""
        self.opcode_name = ""
        self.fmt = ""
        self.obj = None

        if line:
            self.__parse(line)

    def __repr__(self, line_number=""):
        return "%s\n" % \
                (self.buf, )

    def __parse(self, line):
        self.buf = line
        segs = self.buf.split()
        self.opcode_name = segs[0] 
        if INSN_FMT.has_key(self.opcode_name):
            self.fmt = INSN_FMT[self.opcode_name]

        if self.fmt == "35c":
            self.obj = Insn35c(line)
        elif self.fmt == "3rc":
            self.obj = Insn3rc(line)

        log("InsnNode: " + self.opcode_name + " parsed!")

    def reload(self):
        if self.obj:
            self.obj.reload()
            self.buf = self.obj.buf
        else:
            pass


class TryNode(object):

    def __init__(self, line, start, end, handler):
        self.buf = "" 
        self.exception = ""
        self.start = None
        self.end = None
        self.handler = None

        self.__parse(line, start, end, handler)

    def __repr__(self):
        return "Try: %s {%s .. %s} %s" % \
                (self.exception, start.index, end.index, handler.index)

    def __parse(self, line, start, end, handler):
        self.buf = line
        self.start = start
        self.end = end
        end.tries.append(self)
        self.handler = handler
        segs = self.buf.split()
        self.exception = segs[1]

    def reload(self):
        pass

class SwitchNode(object):

    def __init__(self, lines, label):
        self.buf = [] 
        self.type_ = ""
        self.packed_value = ""
        self.packed_labels = []
        self.sparse_dict = {}
        self.label = None

        self.__parse(lines, label)

    def __repr__(self):
        return "Try: %s {%s .. %s} %s" % \
                (self.exception, start.index, end.index, handler.index)

    def __parse(self, lines, label):
        self.buf = lines
        self.label = label
        segs = self.buf[0].split()
        self.type_ = segs[0]
        # TODO:parse more
        label.switch = self 

    def reload(self):
        self.buf = []
        if self.type_ == ".packed-switch":
            self.buf.append("%s %s" % (self.type_, self.packed_value))
            for l in self.packed_labels:
                #l.reload()
                self.buf.append(l.buf)
            self.buf.append(".end packed-switch")
        elif self.type_ == ".sparse-switch":
            self.buf.append(".sparse-switch")
            for value in self.sparse_dict.keys():
                label = self.sparse_dict[value]
                #label.reload()
                self.buf.append("%s -> %s" % (value, label.buf))
            self.buf.append(".end sparse-switch")


class ArrayDataNode(object):

    def __init__(self, lines, label):
        self.buf = [] 
        self.label = None

        self.__parse(lines, label)

    def __repr__(self):
        pass

    def __parse(self, lines, label):
        self.buf = lines
        self.label = label
        # TODO:parse more
        label.array_data = self 

    def reload(self):
        pass

class LabelNode(object):

    def __init__(self, line, index):
        self.name = ""
        self.buf = ""
        self.index = -1
        self.tries = []
        self.switch = None
        self.array_data = None

        self.__parse(line, index)

    def __repr__(self):
        return "Lable: %s\n" % \
                (self.name, )

    def __parse(self, line, index):
        self.buf = line
        self.index = index
        self.name = self.buf[1:]

        log("LabelNode: " + self.name + " parsed!")

    def reload(self):
        self.buf = ":%s" % self.name

class Insn35c(object):

    def __init__(self, line):
        self.buf = ""
        self.opcode_name = ""
        self.registers = []
        self.method_descriptor = ""

        self.__parse(line)

    def __repr__(self):
        return "%s\n" % self.buf

    def __parse(self, line):
        self.buf = line
        tmp = self.buf
        tmp = tmp.replace('{', '')
        tmp = tmp.replace('}', '')
        tmp = tmp.replace(',', '')
        segs = tmp.split()
        self.opcode_name = segs[0]
        self.registers = segs[1:-1]
        self.method_desc = segs[-1]

    def reload(self):
        self.buf = "%s {%s}, %s" % \
                (self.opcode_name, ", ".join(self.registers), \
                self.method_desc)

    def replace(self, opcode_name, method_desc):
        self.opcode_name = opcode_name
        self.method_desc = method_desc

    def set_regs(self, registers):
        self.registers = registers


class Insn3rc(object):

    def __init__(self, line):
        self.buf = ""
        self.opcode_name = ""
        self.reg_start = ""
        self.reg_end = ""
        # self.reg_num = 0
        self.method_descriptor = ""

        self.__parse(line)

    def __repr__(self):
        return "%s\n" % self.buf

    def __parse(self, line):
        self.buf = line
        tmp = self.buf
        tmp = tmp.replace('{', '')
        tmp = tmp.replace('}', '')
        tmp = tmp.replace(',', '')
        tmp = tmp.replace("..", '')
        segs = tmp.split()
        self.opcode_name = segs[0]
        self.reg_start = segs[1]
        self.reg_end = segs[2]
        # self.reg_num = int(self.reg_start[1:]) - int(self.reg_end[1:]) + 1
        self.method_desc = segs[-1]

    def reload(self):
        self.buf = "%s {%s .. %s}, %s" % \
                (self.opcode_name, self.reg_start, self.reg_end, \
                self.method_desc)

    def replace(self, opcode_name, method_desc):
        self.opcode_name = opcode_name
        self.method_desc = method_desc

    def set_reg_start(self, register):
        self.reg_start = register

    def set_reg_end(self, register):
        self.reg_end = register

class TypeNode(object):

    def __init__(self, desc=None):
        self.type_ = ""
        self.dim = 0
        self.basic = None
        self.void = None
        self.words = 1

        if desc:
            self.__parse(desc)

    def __parse(self, desc):
        self.dim = desc.rfind('[') + 1
        desc = desc[self.dim:]

        if BASIC_TYPES.has_key(desc[0]):
            self.type_ = desc[0]
            self.basic = True
            if self.type_ == 'V':
                self.void = True
            else:
                self.void = False
            if (self.type_ == 'J' or self.type_ == 'D') and self.dim == 0:
                self.words = 2
        elif desc[0] == 'L':
            self.type_ = desc
            self.basic = False

    def __repr__(self):
        return self.dim * '[' + self.type_

    def load_java(self, java):
        self.dim = java.count("[]")
        java = java.replace("[]", '')
        if BASIC_TYPES_BY_JAVA.has_key(java):
            self.type_ = BASIC_TYPES_BY_JAVA[java]
            self.basic = True
            if self.type_ == 'V':
                self.void = True
            else:
                self.void = False
            if self.type_ == 'J' or self.type_ == 'D':
                self.words = 2
        else:
            self.type_ = 'L' + java.replace('.', '/') + ';'

    def get_desc(self):
        return self.dim * '[' + self.type_

    def get_java(self):
        if self.basic:
            if self.void:
                return ""
            else:
                return BASIC_TYPES[self.type_] + self.dim * "[]"
        else:
            return self.type_[1:-1].replace('/', '.') + self.dim * "[]"
