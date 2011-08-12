#!/usr/local/bin/python

################################################################################
# (c) 2011, The Honeynet Project
# Author: Patrik Lantz patrik@pjlantz.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
################################################################################

# TODO: dump network traffic and file content on the captured sandbox logs

import sys, json, time, curses
import zipfile, StringIO
from threading import Thread
from xml.dom import minidom
from subprocess import call
from utils import AXMLPrinter
import hashlib
from pylab import *
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.font_manager import FontProperties

sendsms = {}
phonecalls = {}
dataleaks = {}
opennet = {}
sendnet = {}
fdaccess = {}
cryptousage = {}

xml = {}
permissions = []
activities = []
activityaction = {}
services = []
packageNames = []
recvs = []
recvsaction = {}

tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER", 
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_HISTORY",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE" }

class CountingThread(Thread):
    """
    Used for user interface, showing in progress sign 
    and number of collected logs from the sandbox system
    """

    def __init__ (self):
        """
        Constructor
        """
        
        Thread.__init__(self)
        self.stop = False
        self.logs = 0
        
    def stopCounting(self):
        """
        Mark to stop this thread 
        """
        
        self.stop = True
        
    def increaseCount(self):
        
        self.logs = self.logs + 1

    def run(self):
        """
        Update the progress sign and 
        number of collected logs
        """
        
        signs = ['|', '/', '-', '\\']
        counter = 0
        while 1:
            sign = signs[counter % len(signs)]
            sys.stdout.write("     \033[1;32m[%s] Collected %s sandbox logs\033[1;m   (Ctrl-C to view logs)\r" % (sign, str(self.logs)))
            sys.stdout.flush()
            time.sleep(0.5)
            counter = counter + 1
            if self.stop:
                sys.stdout.write("   \033[1;32m[%s] Collected %s sandbox logs\033[1;m%s\r" % ('*', str(self.logs), ' '*25))
                sys.stdout.flush()
                break
                
class ActivityThread(Thread):
    """
    Run until all activities and services 
    within an APK have been started
    """

    def __init__ (self):
        """
        Constructor
        """
        
        Thread.__init__(self)
        
    def run(self):
        """
        Run each service and activity found in Manifest
        """

        runActivity = ''
        runPackage = ''
        for activity in activities:
            if activity[0] == '.':
                runActivity = activity
                runPackage = packageNames[0]
            else:
                for package in packageNames:
                    splitAct = activity.split(package)
                    if len(splitAct) > 1:
                        runActivity = splitAct[1]
                        runPackage = package
                        break
            call(['./monkeyrunner', 'monkeyrunner.py', apkName, runPackage, runActivity])
            time.sleep(5)
            
        runService = ''
        runPackage = ''
        for service in services:
            if service[0] == '.':
                runService = service
                runPackage = packageNames[0]
            else:
                for package in packageNames:
                    splitServ = service.split(package)
                    if len(splitServ) > 1:
                        runService = splitServ[1]
                        runPackage = package
                        break
            call(['./monkeyrunner', 'monkeyrunner.py', apkName, runPackage, runService])
            time.sleep(5)
            
def fileHash(f, block_size=2**8):
    """
    Calculate MD5,SHA-1, SHA-256
    hashes of APK input file
    """
    
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    f = open(f, 'rb')
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]

def getTags(tagParam):
    """
    Retrieve the tag names found within a tag
    """
    
    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound

try:
    fd = open( sys.argv[1], "rb" )
except:
    if len(sys.argv) > 1:
        print "File " + sys.argv[1] + " not found"
    else:
        print "Usage: ../platform-tools/adb logcat dalvikvm:W *:S | ./logcatfilter.py file.APK"
    sys.exit(1)
apkName = sys.argv[1]
raw = fd.read()
fd.close()
zip = zipfile.ZipFile( StringIO.StringIO( raw ) )
for i in zip.namelist() :
 if i == "AndroidManifest.xml" :
    try :
       xml[i] = minidom.parseString( zip.read( i ) )
    except :
       xml[i] = minidom.parseString( AXMLPrinter( zip.read( i ) ).getBuff() )
       for item in xml[i].getElementsByTagName('manifest'):
          packageNames.append( str( item.getAttribute("package") ) )
       for item in xml[i].getElementsByTagName('uses-permission'):
          permissions.append( str( item.getAttribute("android:name") ) )
       for item in xml[i].getElementsByTagName('receiver'):
          recvs.append( str( item.getAttribute("android:name") ) )
          for child in item.getElementsByTagName('action'):
              recvsaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))
       for item in xml[i].getElementsByTagName('service'):
          services.append( str( item.getAttribute("android:name") ) )
       for item in xml[i].getElementsByTagName('activity'):
          activities.append( str( item.getAttribute("android:name") ) )
          for child in item.getElementsByTagName('action'):
              activityaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))
              
curses.setupterm()
sys.stdout.write(curses.tigetstr("clear"))
sys.stdout.flush()

print " ____                        __  ____"               
print "/\  _`\    [\033[1;31malpha\033[1;m]    __    /\ \/\  _`\\"                  
print "\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"  
print " \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\" 
print "  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
print "   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
print "    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"

count = CountingThread()
count.start()
actexec = ActivityThread()
actexec.start()
call(['../platform-tools/adb', 'logcat', '-c'])
timeStamp = time.time()

while 1:
    try:
        logcatInput = sys.stdin.readline()
        if not logcatInput:
            break
        taintlog = logcatInput.split('TaintLog:')
        if len(taintlog) > 1:
            try:
                parseKey = taintlog[1].split('{')
                if len(parseKey) > 1:
                    key = parseKey[1].split(':')[0].replace('\"', '').strip()
                    # File access log
                    if key == 'FdAccess':
                        temp = {}
                        operation = parseKey[2].split('operation\":')[1].split(',')[0]
                        fd = parseKey[2].split('fd\":')[1].split(',')[0]
                        path = parseKey[2].split('path\":')[1].split('} }')[0]
                        temp['operation'] = operation.replace('\"', '').strip()
                        if temp['operation'] == 'write':
                            temp['type'] = 'file write'
                        else:
                            temp['type'] = 'file read'
                        temp['fd'] = fd.replace('\"', '').strip()
                        temp['path'] = path.replace('\"', '').strip()
                        fdaccess[time.time()-timeStamp] = temp
                        count.increaseCount()
                    # opened network connection log
                    if key == 'OpenNet':
                        temp = {}
                        desthost = parseKey[2].split('desthost\":')[1].split(',')[0]
                        temp['desthost'] = desthost.replace('\"', '').strip()
                        destport = parseKey[2].split('destport\":')[1].split('} }')[0]
                        temp['destport'] = destport.replace('\"', '').strip()
                        temp['type'] = 'net open'                                                
                        opennet[time.time()-timeStamp] = temp
                        count.increaseCount()
                    # outgoing network activity log
                    if key == 'SendNet':
                        temp = {}
                        desthost = parseKey[2].split('desthost\":')[1].split(',')[0]
                        temp['desthost'] = desthost.replace('\"', '').strip()
                        destport = parseKey[2].split('destport\":')[1].split(',')[0]
                        temp['destport'] = destport.replace('\"', '').strip() 
                        data = parseKey[2].split('data\":')[1].split('} }')[0]
                        temp['data'] = data.replace('\"', '').strip()        
                        temp['type'] = 'net write'                                                                
                        sendnet[time.time()-timeStamp] = temp
                        count.increaseCount()                                          
                    # data leak log
                    if key == 'DataLeak':
                        temp = {}
                        sink = parseKey[2].split('sink\":')[1].split(',')[0]
                        temp['sink'] = sink.replace('\"', '').strip()
                        if temp['sink'] == 'Network':
                            desthost = parseKey[2].split('desthost\":')[1].split(',')[0]
                            temp['desthost'] = desthost.replace('\"', '').strip()
                            destport = parseKey[2].split('destport\":')[1].split(',')[0]
                            temp['destport'] = destport.replace('\"', '').strip()
                            data = parseKey[2].split('data\":')[1].split('} }')[0]                           
                            temp['data'] = data.split('HTTP/1.1')[0].split('\"')[1].strip()
                        if temp['sink'] == 'File':
                            fd = parseKey[2].split('fd\":')[1].split(',')[0]
                            temp['fd'] = fd.replace('\"', '').strip()
                        if temp['sink'] == 'SMS':
                            number = parseKey[2].split('number\":')[1].split(',')[0]
                            temp['number'] = number.replace('\"', '').strip()
                            data = parseKey[2].split('data\":')[1].split('} }')[0]                            
                            temp['data'] = data.split('HTTP/1.1')[0].split('\"')[1].strip()         
                        tag = parseKey[2].split('tag\":')[1].split(',')[0]
                        temp['type'] = 'leak'
                        temp['tag'] = tag.replace('\"', '').strip()
                        dataleaks[time.time()-timeStamp] = temp
                        count.increaseCount()
                    # sent sms log
                    if key == 'SendSMS':
                        temp = {}
                        number = parseKey[2].split('number\":')[1].split(',')[0]
                        temp['number'] = number.replace('\"', '').strip()                        
                        message = parseKey[2].split('message\":')[1].split('} }')[0]                           
                        temp['message'] = message.replace('\"', '').strip()
                        temp['type'] = 'sms'
                        sendsms[time.time()-timeStamp] = temp
                        count.increaseCount()
                    # phone call log
                    if key == 'PhoneCall':
                        temp = {}
                        number = parseKey[2].split('number\":')[1].split('} }')[0]                           
                        temp['number'] = number.replace('\"', '').strip()
                        temp['type'] = 'call'
                        phonecalls[time.time()-timeStamp] = temp
                        count.increaseCount()
                    # crypto api usage log
                    if key == 'CryptoUsage':
                        temp = {}
                        operation = parseKey[2].split('operation\":')[1].split(',')[0]
                        temp['operation'] = operation.replace('\"', '').strip()
                        if temp['operation'] == 'keyalgo':
                            key = parseKey[2].split('key\":')[1].split(', \"algorithm\"')[0]
                            temp['key'] = key.replace('\"', '').strip()
                            algorithm = parseKey[2].split('algorithm\":')[1].split('} }')[0]                           
                            temp['algorithm'] = algorithm.replace('\"', '').strip()
                        else:
                            algorithm = parseKey[2].split('algorithm\":')[1].split(',')[0]
                            temp['algorithm'] = algorithm.replace('\"', '').strip()
                            data = parseKey[2].split('data\":')[1].split('} }')[0]                           
                            temp['data'] = data.replace('\"', '').strip()
                        temp['type'] = 'crypto'                                                                   
                        cryptousage[time.time()-timeStamp] = temp
                        count.increaseCount()
            except ValueError:
                pass

    except KeyboardInterrupt:
        # Wait for counting thread to stop
        count.stopCounting()
        count.join()
        break

print ''
space = ' ' * 5
space2 = ' ' * 8
space3 = ' ' * 11

hash = fileHash(apkName)
print "\n\n" + space + "\033[1;48m[Info]\033[1;m\n" + space + "------"
print "%s\033[1;36m%s\033[1;m\t%s" % (space2, "File name:", apkName)
print "%s\033[1;36m%s\033[1;m\t\t%s" % (space2, "MD5:", hash[0])
print "%s\033[1;36m%s\033[1;m\t\t%s" % (space2, "SHA1:", hash[1])
print "%s\033[1;36m%s\033[1;m\t\t%s" % (space2, "SHA256:", hash[2])
print "%s\033[1;36m%s\033[1;m\t%s" % (space2, "Duration:", str(time.time() - timeStamp) + "s") 

# Print file activity
keys = fdaccess.keys()
keys.sort()
print "\n\n" + space + "\033[1;48m[File activities]\033[1;m\n" + space + "-----------------\n"
print space2 + '\033[1;48m[Read operations]\033[1;m\n' + space2 + '-----------------'
path = list()
for key in keys:
    temp = fdaccess[key]
    try:
        if temp['operation'] == 'read':
            print "%s[\033[1;36m%s\033[1;m]\t\t%s Fd: %s" % (space3, str(key), temp['path'], temp['fd'])
    except ValueError:
        pass
    except KeyError:
        pass
print ''
print space2 + '\033[1;48m[Write operations]\033[1;m\n' + space2 + '------------------'
for key in keys:                                                       
    temp = fdaccess[key]
    try:
        if temp['operation'] == 'write':
            print "%s[\033[1;36m%s\033[1;m]\t\t%s Fd: %s" % (space3, str(key), temp['path'], temp['fd'])
    except ValueError:
        pass
    except KeyError:
        pass 

# Print crypto API usage
keys = cryptousage.keys()
keys.sort()
print "\n" + space + "\033[1;48m[Crypto API activities]\033[1;m\n" + space + "-----------------------"
for key in keys:                                                               
    temp = cryptousage[key]
    try:
        if temp['operation'] == 'keyalgo':
            print "%s[\033[1;36m%s\033[1;m]\t\t Key:{%s} Algorithm: %s" % (space3, str(key), temp['key'], temp['algorithm'])
        else:
            print "%s[\033[1;36m%s\033[1;m]\t\t Operation:{%s} Algorithm: %s" % (space3, str(key), temp['operation'], temp['algorithm'])
            print "%s\t\t\t\t Data:{%s}" % (space3, temp['data']) + '\n'
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''

# TODO: Print incoming network communication
print space + "\033[1;48m[Network activity]\033[1;m\n" + space + "------------------\n"
print space2 + "\033[1;48m[Opened connections]\033[1;m\n" + space2 + "--------------------"
keys = opennet.keys()
keys.sort()
for key in keys:
    temp = opennet[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Destination: %s Port: %s" % (space3, str(key), temp['desthost'], temp['destport'])
    except ValueError:
        pass
    except KeyError:
        pass
print "\n" + space2 + "\033[1;48m[Outgoing traffic]\033[1;m\n" + space2 + "------------------"
keys = sendnet.keys()
keys.sort()
for key in keys:
    temp = sendnet[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Destination: %s Port: %s" % (space3, str(key), temp['desthost'], temp['destport'])
        print "%s\t\t\t\t Data: %s" % (space3, temp['data']) + '\n'
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''

print space + "\033[1;48m[Intent receivers]\033[1;m\n" + space + "------------------"
for recv in recvsaction:
    print "%s\033[1;36m%s\033[1;m\t\t\t Action: %s" % (space3, recv, recvsaction[recv])

# TODO: Print bypassed permissions
print "\n" + space + "\033[1;48m[Permissions bypassed]\033[1;m\n" + space + "----------------------"

# Print data leaks
keys = dataleaks.keys()
keys.sort()
print "\n" + space + "\033[1;48m[Information leakage]\033[1;m\n" + space + "---------------------"
for key in keys:
    temp = dataleaks[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Sink: %s" % (space3, str(key), temp['sink'])
        if temp['sink'] == 'Network':
            print "%s\t\t\t\t Destination: %s" % (space3, temp['desthost'])
            print "%s\t\t\t\t Port: %s" % (space3, temp['destport'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))
            print "%s\t\t\t\t Data: %s" % (space3, temp['data'])

        if temp['sink'] == 'File':
            print "%s\t\t\t\t File descriptor: %s" % (space3, temp['fd'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))

        if temp['sink'] == 'SMS':
            print "%s\t\t\t\t Number: %s" % (space3, temp['number'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))
            print "%s\t\t\t\t Data: %s" % (space3, temp['data'])
        print ''
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''

# Print sent SMSs
keys = sendsms.keys()
keys.sort()
print space + "\033[1;48m[Sent SMS]\033[1;m\n" + space + "----------"
for key in keys:
    temp = sendsms[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Number: %s" % (space3, str(key), temp['number'])
        print "%s\t\t\t\t Message: %s" % (space3, temp['message'])
    except ValueError:
        pass
    except KeyError:
        pass
        
# Print phone calls
keys = phonecalls.keys()
keys.sort()
print "\n" + space + "\033[1;48m[Phone calls]\033[1;m\n" + space + "-------------"
for key in keys:
    temp = phonecalls[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Number: %s" % (space3, str(key), temp['number'])
    except ValueError:
        pass
    except KeyError:
        pass
        


# Generate APK behavior graph
labels = {'begin':0, 'call':1, 'sms':2, 
          'leak':3, 'file read':4, 'file write':5, 
          'net open': 6, 'net read':7, 'net write':8, 
          'crypto':9, 'end':10 }

result = list()
predict = list()
mergedLogs = dict(phonecalls.items() + sendsms.items() + dataleaks.items() + cryptousage.items() +
                  opennet.items() + sendnet.items() + fdaccess.items())
keys = mergedLogs.keys()
keys.sort()
for key in keys:
    result.append(key)
    temp = mergedLogs[key]
    predict.append(labels[temp['type']])

ax = gca()
ax.plot(result, predict, c='r', marker='o', linewidth=2)
ax.set_yticks((0,1,2,3,4,5,6,7,8, 9, 10))

# Add y-axis labes
ylabels = []
for key, value in sorted(labels.iteritems(), key=lambda (k,v): (v,k)):
    if key == 'begin' or key == 'end':
        key = ''
    ylabels.append(key)
ax.set_yticklabels(ylabels)

# Create zebra stripes on y-axis
yTickPos,_ = plt.yticks()
yTickPos = yTickPos[:-1]
ax.barh(yTickPos, [max(plt.xticks()[0])] * len(yTickPos), height=(yTickPos[1]-yTickPos[0]), color=['#FFFFCC','w'], linewidth=0.0)
grid(True)

xlabel('timestamp', {'fontsize': 18})
ylabel('activity', {'fontsize': 18})
ax.set_xlim(result[0], result[len(result)-1])

# Save figure
title(apkName)
F = gcf()
DefaultSize = F.get_size_inches()
F.set_size_inches( (DefaultSize[0]*1.2, DefaultSize[1]*1.2) )
Size = F.get_size_inches()
savefig("behaviorgraph.png")
print "\n\nSaved APK behavior graph as: \033[1;32mbehaviorgraph.png\033[1;m"
plt.clf()



# Generate treemap 
NODE_CHILDREN = ['CALL', 'SMSSEND', 'SMSLEAK', 'FILEWRITE', 'FILEREAD', 'FILELEAK',
                 'NETOPEN', 'NETWRITE', 'NETREAD', 'NETLEAK', 'CRYPTKEY', 'CRYPTDEC', 'CRYPTENC']
MAP_COLORS = {'CALL': "#66cdaa", 'SMSSEND': "#8fbc8f", 'SMSLEAK': '#2e8b57', 'FILEWRITE': '#ffd700',
              'FILEREAD': '#eedd82', 'FILELEAK': '#daa520', 'NETOPEN': '#c80000', 'NETWRITE': '#cd5c5c', 
              'NETREAD': '#bc8f8f', 'NETLEAK': '#8b4513', 'CRYPTKEY': '#6495ed', 'CRYPTDEC': '#483d8b', 
              'CRYPTENC': '#6a5acd'}

class Treemap:

    def __init__(self, tree, iter_method, size_method, color_method):
        """
        Create a tree map from tree, using itermethod(node) to walk tree,
        size_method(node) to get object size and color_method(node) to get its 
        color
        """

        self.ax = gca()
        subplots_adjust(left=0, right=1, top=1, bottom=0)
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self.treemapIter = 0

        self.size_method = size_method
        self.iter_method = iter_method
        self.color_method = color_method
        self.addnode(tree)
        
        # Legend box
        """box = self.ax.get_position()
        self.ax.set_position([box.x0, box.y0, box.width * 0.8, box.height])
        self.ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05),
                       fancybox=True, shadow=True, ncol=5)"""

    def addnode(self, node, lower=[0,0], upper=[1,1], axis=0):
        axis = axis % 2
        self.draw_rectangle(lower, upper, node)
        width = upper[axis] - lower[axis]
        if not isinstance(node, tuple):
            self.treemapIter = self.treemapIter + 1
        try:
            for child in self.iter_method(node):
                upper[axis] = lower[axis] + (width * float(size(child))) / size(node)
                self.addnode(child, list(lower), list(upper), axis + 1)
                lower[axis] = upper[axis]
        except TypeError:
            pass

    def draw_rectangle(self, lower, upper, node):
        if not isinstance(node, tuple):
            r = Rectangle(lower, upper[0]-lower[0], upper[1] - lower[1],
                          edgecolor='k', linewidth=0.3,
                          facecolor= self.color_method(node, self.treemapIter), 
                          label=NODE_CHILDREN[self.treemapIter])
            self.ax.add_patch(r)
                     
size_cache = {}
def size(thing):
    if isinstance(thing, int):
        return thing
    if thing in size_cache:
        return size_cache[thing]
    else:
        size_cache[thing] = reduce(int.__add__, [size(x) for x in thing])
        return size_cache[thing]
def set_color(thing, iternbr):
    return MAP_COLORS[NODE_CHILDREN[iternbr]]

tree = list()
# get phone call actions
calls = len(phonecalls)
tree.append(calls)
# get sms actions
sms = list()
smssend = len(sendsms)
sms.append(smssend)
count = 0
for k, v in dataleaks.items():
    if v['sink'] == 'SMS':
        count = count + 1
sms.append(count)
tree.append(tuple(sms))
# get file operations
file = list()
countw = 0
countr = 0
for k,v in fdaccess.items():
    if v['operation'] == 'read':
        countr = countr + 1
    else:
        countw = countw = 1
file.append(countw)
file.append(countr)
count = 0
for k,v in dataleaks.items():
    if v['sink'] == 'File':
        count = count + 1
file.append(count)
tree.append(tuple(file))
# get network operations
network = list()
network.append(len(opennet))
network.append(len(sendnet))
network.append(0) # net read
count = 0
for k,v in dataleaks.items():
    if v['sink'] == 'Network':
        count = count + 1
network.append(count)
tree.append(tuple(network))
# get crypto operations
crypto = list()
countk = 0
countd = 0
counte = 0
for k,v in cryptousage.items():
    if v['operation'] == 'keyalgo':
        countk = countk + 1
    if v['operation'] == 'encryption':
        counte = counte + 1
    if v['operation'] == 'decryption':
        countd = countd + 1
crypto.append(countk)
crypto.append(countd)
crypto.append(counte)
tree.append(tuple(crypto))
tree = tuple(tree)

Treemap(tree, iter, size, set_color)
xlabel('section', {'fontsize': 18})
ylabel('operation', {'fontsize': 18})
title(apkName)
F = gcf()
DefaultSize = F.get_size_inches()
F.set_size_inches( (DefaultSize[0]*0.9, DefaultSize[1]*0.9))
Size = F.get_size_inches()
savefig('tree.png', bbox_inches = 'tight', pad_inches = 0.2)
print "Saved treemap graph as: \033[1;32mtree.png\033[1;m"
