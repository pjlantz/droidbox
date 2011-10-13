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

import sys, json, time, curses
import zipfile, StringIO
from threading import Thread
from xml.dom import minidom
from subprocess import call, PIPE
from utils import AXMLPrinter
import hashlib
from pylab import *
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle
from matplotlib.font_manager import FontProperties

sendsms = {}
phonecalls = {}
cryptousage = {}
netbuffer = {}

dexclass = {}
dataleaks = {}
opennet = {}
sendnet = {}
recvnet = {}
fdaccess = {}
servicestart = {}
xml = {}
udpConn = []
permissions = []
activities = []
activityaction = {}
enfperm = []
packageNames = []
recvs = []
recvsaction = {}
accessedfiles = {}

tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER", 
         0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
         0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
         0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
         0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
         0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }

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
    Run until the main Activity 
    within an APK have been started
    """

    def __init__ (self):
        """
        Constructor
        """
        
        Thread.__init__(self)
        
    def run(self):
        """
        Run main activity found in Manifest
        """

        runActivity = ''
        runPackage = ''
        for activity in activities:
            if activityaction.has_key(activity) and activityaction[activity] == 'android.intent.action.MAIN':
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
                
                call(['monkeyrunner', 'scripts/monkeyrunner.py', apkName, runPackage, runActivity], stderr=PIPE)
                
                break
            
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
    
def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """
 
    bytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        bytes.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join( bytes )
    
def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')

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
        print "Usage: ./droidbox.sh filename.apk"
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
       for item in xml[i].getElementsByTagName('permission'):
          enfperm.append( str( item.getAttribute("android:name") ) )
       for item in xml[i].getElementsByTagName('uses-permission'):
          permissions.append( str( item.getAttribute("android:name") ) )
       for item in xml[i].getElementsByTagName('receiver'):
          recvs.append( str( item.getAttribute("android:name") ) )
          for child in item.getElementsByTagName('action'):
              recvsaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))
       for item in xml[i].getElementsByTagName('activity'):
          activities.append( str( item.getAttribute("android:name") ) )
          for child in item.getElementsByTagName('action'):
              activityaction[str( item.getAttribute("android:name") )] = (str( child.getAttribute("android:name") ))
              
curses.setupterm()
sys.stdout.write(curses.tigetstr("clear"))
sys.stdout.flush()
call(['adb', 'logcat', '-c'])

print " ____                        __  ____"               
print "/\  _`\               __    /\ \/\  _`\\"                  
print "\ \ \/\ \  _ __  ___ /\_\   \_\ \ \ \L\ \   ___   __  _"  
print " \ \ \ \ \/\`'__\ __`\/\ \  /'_` \ \  _ <' / __`\/\ \/'\\" 
print "  \ \ \_\ \ \ \/\ \L\ \ \ \/\ \L\ \ \ \L\ \\ \L\ \/>  </"
print "   \ \____/\ \_\ \____/\ \_\ \___,_\ \____/ \____//\_/\_\\"
print "    \/___/  \/_/\/___/  \/_/\/__,_ /\/___/ \/___/ \//\/_/"

count = CountingThread()
count.start()
actexec = ActivityThread()
actexec.start()
timeStamp = time.time()
while 1:
    try:
        logcatInput = sys.stdin.readline()
        if not logcatInput:
            break
        boxlog = logcatInput.split('DroidBox:')
        if len(boxlog) > 1:
            try:
            	load = json.loads(decode(boxlog[1]))
            	# DexClassLoader
            	if load.has_key('DexClassLoader'):
            	    load['DexClassLoader']['type'] = 'dexload'
            	    dexclass[time.time() - timeStamp] = load['DexClassLoader']
            	    count.increaseCount()
            	# service started
            	if load.has_key('ServiceStart'):
            	    load['ServiceStart']['type'] = 'service'
            	    servicestart[time.time() - timeStamp] = load['ServiceStart']
            	    count.increaseCount()
                # received data from net
                if load.has_key('RecvNet'):   
                    host = load['RecvNet']['srchost']
                    port = load['RecvNet']['srcport']
                    if load['RecvNet'].has_key('type') and load['RecvNet']['type'] == 'UDP':
                        recvdata = { 'host': host, 'port': port, 'data': load['RecvNet']['data']}
                        recvnet[time.time() - timeStamp] = recvdata
                        count.increaseCount()
                    else:
                        fd = load['RecvNet']['fd']  
                        hostport = host + ":" + port + ":" + fd 
                        if netbuffer.has_key(hostport):
                            if len(netbuffer[hostport]) == 0:
                                netbuffer[hostport] = str(time.time()-timeStamp) + ":"
                            netbuffer[hostport] =  netbuffer[hostport] + load['RecvNet']['data']
                # fdaccess
                if load.has_key('FdAccess'):
                    accessedfiles[load['FdAccess']['id']] = load['FdAccess']['path']
                # file read or write     
                if load.has_key('FileRW'):
                    if accessedfiles.has_key(load['FileRW']['id']) and not "/dev/pts" in accessedfiles[load['FileRW']['id']]:
                        load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
                        if load['FileRW']['operation'] == 'write':
                            load['FileRW']['type'] = 'file write'
                        else:
                            load['FileRW']['type'] = 'file read'
                        fdaccess[time.time()-timeStamp] = load['FileRW']
                        count.increaseCount()
                # opened network connection log
                if load.has_key('OpenNet'):
                    if load['OpenNet'].has_key('type') and load['OpenNet']['type'] == 'UDP':
                        opennet[time.time()-timeStamp] = load['OpenNet']
                        ref = load['OpenNet']['desthost'] + load['OpenNet']['destport']
                        if ref not in udpConn:
                            udpConn.append(ref)
                    else:
                        load['OpenNet']['type'] = 'net open'                                                
                        opennet[time.time()-timeStamp] = load['OpenNet']
                        host = load['OpenNet']['desthost']
                        port = load['OpenNet']['destport']
                        fd = load['OpenNet']['fd']
                        netbuffer[host + ":" + port + ":" + fd] = ""
                    count.increaseCount()
                # closed socket
                if load.has_key('CloseNet'):
                    host = load['CloseNet']['desthost']
                    port = load['CloseNet']['destport']
                    ref = host + ":" + port
                    if ref not in udpConn:
                        fd = load['CloseNet']['fd']
                        try:
                            data = netbuffer[host + ":" + port + ":" + fd]
                        except KeyError:
                            continue
                        stamp = float(data.split(":")[0])
                        buffer = data.split(":")[1]
                        recvdata =  { 'host': host, 'port': port, 'data': buffer}
                        recvnet[stamp] = recvdata
                        netbuffer[host + ":" + port + ":" + fd] = ""
                        count.increaseCount()
                    else:
                        ref.remove(ref)
                # outgoing network activity log
                if load.has_key('SendNet'):
                    if load['SendNet'].has_key('type') and load['SendNet']['type'] == 'UDP':
                        ref = load['SendNet']['desthost'] + load['SendNet']['destport']
                        if ref not in udpConn:
                            udpConn.append(ref)
                            opennet[time.time()-timeStamp] = load['SendNet']
                    load['SendNet']['type'] = 'net write'                                                               
                    sendnet[time.time()-timeStamp] = load['SendNet']
                    count.increaseCount()                                          
                # data leak log
                if load.has_key('DataLeak'):                   
                    if load['DataLeak']['sink'] == 'File':
                        if accessedfiles.has_key(load['DataLeak']['id']):
                            load['DataLeak']['path'] = accessedfiles[load['DataLeak']['id']]          
                    load['DataLeak']['type'] = 'leak'
                    dataleaks[time.time()-timeStamp] = load['DataLeak']
                    count.increaseCount()
                # sent sms log
                if load.has_key('SendSMS'):
                    load['SendSMS']['type'] = 'sms'
                    sendsms[time.time()-timeStamp] = load['SendSMS']
                    count.increaseCount()
                # phone call log
                if load.has_key('PhoneCall'):
                    load['PhoneCall']['type'] = 'call'
                    phonecalls[time.time()-timeStamp] = load['PhoneCall']
                    count.increaseCount()
                # crypto api usage log
                if load.has_key('CryptoUsage'):
                    load['CryptoUsage']['type'] = 'crypto'                                                                   
                    cryptousage[time.time()-timeStamp] = load['CryptoUsage']
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
            print "%s[\033[1;36m%s\033[1;m]\t\t Path: %s" % (space3, str(key), hexToStr(temp['path']))
            print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + '\n'
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
            print "%s[\033[1;36m%s\033[1;m]\t\t Path: %s" % (space3, str(key), hexToStr(temp['path']))
            print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + '\n'
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

# print network activity
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
        print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data'])) + '\n'
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''
print "\n" + space2 + "\033[1;48m[Incoming traffic]\033[1;m\n" + space2 + "------------------"
keys = recvnet.keys()
keys.sort()
for key in keys:
    temp = recvnet[key]
    try:
        print "%s[\033[1;36m%s\033[1;m]\t\t Source: %s Port: %s" % (space3, str(key), temp['host'], temp['port'])
        print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data']) + '\n')
    except ValueError:
        pass
    except KeyError:
        pass
if len(keys) == 0:
    print ''
    
# print DexClass initializations
print space + "\033[1;48m[DexClassLoader]\033[1;m\n" + space + "-----------------"
keys = dexclass.keys()
keys.sort()
for key in keys:
    temp = dexclass[key]
    try:
        print "%s\033[1;36m%s\033[1;m\t\t\t Path: %s\n" % (space3, str(key), temp['path'])
    except ValueError:
        pass
    except KeyError:
        pass
        
# print registered broadcast receivers
print space + "\033[1;48m[Broadcast receivers]\033[1;m\n" + space + "---------------------"
for recv in recvsaction:
    print "%s\033[1;36m%s\033[1;m\t\t\t Action: %s\n" % (space3, recv, recvsaction[recv])
    
# list started services
print space + "\033[1;48m[Started services]\033[1;m\n" + space + "------------------"
keys = servicestart.keys()
keys.sort()
for key in keys:
    temp = servicestart[key]
    print "%s\033[1;36m%s\033[1;m\t\t\t Class: %s\n" % (space3, str(key), temp['name'])
    
# print enforced permissions
print space + "\033[1;48m[Enforced permissions]\033[1;m\n" + space + "----------------------"
for perm in enfperm:
    print "%s\033[1;36m%s\033[1;m" % (space3, perm)

# print bypassed permissions
print "\n" + space + "\033[1;48m[Permissions bypassed]\033[1;m\n" + space + "----------------------"

if len(recvnet.keys()) > 0 or len(sendnet.keys()) > 0 or len(opennet.keys()) > 0:
    if 'android.permission.INTERNET' not in permissions:
        print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.INTERNET')
if len(sendsms.keys()) > 0 and 'android.permission.SEND_SMS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.SEND_SMS')
if len(phonecalls.keys()) > 0 and 'android.permission.CALL_PHONE' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.CALL_PHONE')
if 'android.provider.Telephony.SMS_RECEIVED' in recvsaction and 'android.permission.RECEIVE_SMS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.RECEIVE_SMS')
    
contacts = False
phonestate = False
sms = False
book = False
for k in dataleaks.keys():	

    tagsInLeak = getTags(int(dataleaks[k]['tag'], 16))
    
    if 'TAINT_CONTACTS' in tagsInLeak or 'TAINT_CALL_LOG' in tagsInLeak:
        contacts = True
    if 'TAINT_IMEI' in tagsInLeak:
        phonestate = True
    if 'TAINT_IMSI' in tagsInLeak:
        phonestate = True
    if 'TAINT_PHONE_NUMBER' in tagsInLeak:
        phonestate = True
    if 'TAINT_SMS' in tagsInLeak:
        sms = True
    if 'TAINT_BROWSER' in tagsInLeak:
        book = True

if contacts and 'android.permission.READ_CONTACTS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.READ_CONTACTS')
if phonestate and 'android.permission.READ_PHONE_STATE' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.READ_PHONE_STATE')
if sms and 'android.permission.READ_SMS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'android.permission.READ_SMS')
if book and 'com.android.browser.permission.READ_HISTORY_BOOKMARKS' not in permissions:
    print "%s\033[1;36m%s\033[1;m" % (space3, 'com.android.browser.permission.READ_HISTORY_BOOKMARKS')
    
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
            print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data']))

        if temp['sink'] == 'File':
            print "%s\t\t\t\t Path: %s" % (space3, hexToStr(temp['path']))
            print "%s\t\t\t\t Operation: %s" % (space3, temp['operation'])
            print "%s\t\t\t\t Tag: %s" % (space3, ', '.join(getTags(int(temp['tag'], 16))))
            print "%s\t\t\t\t Data: %s" % (space3, hexToStr(temp['data']))

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
labels = {'begin':0, 'dexload':1, 'service': 2, 'call':3, 'sms':4, 
          'leak':5, 'file read':6, 'file write':7, 
          'net open': 8, 'net read':9, 'net write':10, 
          'crypto':11, 'end':12 }

result = list()
predict = list()
mergedLogs = dict(dexclass.items() + servicestart.items() + phonecalls.items() + sendsms.items() + 
                  dataleaks.items() + cryptousage.items() + opennet.items() + sendnet.items() + fdaccess.items())
keys = mergedLogs.keys()
keys.sort()
for key in keys:
    result.append(key)
    temp = mergedLogs[key]
    predict.append(labels[temp['type']])

ax = gca()
ax.plot(result, predict, c='r', marker='o', linewidth=2)
ax.set_yticks((0,1,2,3,4,5,6,7,8, 9, 10, 11, 12))

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
try:
    ax.set_xlim(result[0], result[len(result)-1])
except:
    sys.exit(1)

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
NODE_CHILDREN = ['DEXLOAD', 'SERVICE', 'CALL', 'SMSSEND', 'SMSLEAK', 'FILEWRITE', 'FILEREAD', 'FILELEAK',
                 'NETOPEN', 'NETWRITE', 'NETREAD', 'NETLEAK', 'CRYPTKEY', 'CRYPTDEC', 'CRYPTENC']
MAP_COLORS = {'DEXLOAD': '#008080', 'SERVICE': '#00ffff', 'CALL': "#66cdaa", 'SMSSEND': "#8fbc8f", 
              'SMSLEAK': '#2e8b57', 'FILEWRITE': '#ffd700',
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
        self.tree = tree
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
                if child != 0:
                    upper[axis] = lower[axis] + (width * float(size(child))) / size(node)
                    self.addnode(child, list(lower), list(upper), axis + 1)
                    lower[axis] = upper[axis]
                else:
                    self.treemapIter = self.treemapIter + 1
        except TypeError:
            pass
        except ZeroDivisionError:
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
# get started services and class loads
dexloadservice = list()
dexloads = len(dexclass)
dexloadservice.append(dexloads)
services = len(servicestart)
dexloadservice.append(services)
tree.append(tuple(dexloadservice))

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
network.append(len(recvnet))
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
F.set_size_inches( (DefaultSize[0]*1.5, DefaultSize[1]*1.5))
Size = F.get_size_inches()
savefig('tree.png', bbox_inches = 'tight', pad_inches = 0.2)
print "Saved treemap graph as: \033[1;32mtree.png\033[1;m"
sys.exit(1)
