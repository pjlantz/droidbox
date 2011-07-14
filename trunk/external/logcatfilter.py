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
# Additionally: log monitored intents and bypassed permissions when static pre-check
# is implemented.

import sys, json, time, curses
from threading import Thread

sendsms = {}
phonecalls = {}
dataleaks = {}
opennet = {}
sendnet = {}
fdaccess = {}
cryptousage = {}

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
            
def getTags(tagParam):
    """
    Retrieve the tag names found within a tag
    """
    
    tagsFound = []
    for tag in tags.keys():
        if tagParam & tag != 0:
            tagsFound.append(tags[tag])
    return tagsFound

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
                        temp['fd'] = fd.replace('\"', '').strip()
                        temp['path'] = path.replace('\"', '').strip()
                        fdaccess[time.time()] = temp
                        count.increaseCount()
                    # opened network connection log
                    if key == 'OpenNet':
                        temp = {}
                        desthost = parseKey[2].split('desthost\":')[1].split(',')[0]
                        temp['desthost'] = desthost.replace('\"', '').strip()
                        destport = parseKey[2].split('destport\":')[1].split('} }')[0]
                        temp['destport'] = destport.replace('\"', '').strip()                                                 
                        opennet[time.time()] = temp
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
                        sendnet[time.time()] = temp
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
                        temp['tag'] = tag.replace('\"', '').strip()
                        dataleaks[time.time()] = temp
                        count.increaseCount()
                    # sent sms log
                    if key == 'SendSMS':
                        temp = {}
                        number = parseKey[2].split('number\":')[1].split(',')[0]
                        temp['number'] = number.replace('\"', '').strip()                        
                        message = parseKey[2].split('message\":')[1].split('} }')[0]                           
                        temp['message'] = message.replace('\"', '').strip()
                        sendsms[time.time()] = temp
                        count.increaseCount()
                    # phone call log
                    if key == 'PhoneCall':
                        temp = {}
                        number = parseKey[2].split('number\":')[1].split('} }')[0]                           
                        temp['number'] = number.replace('\"', '').strip()
                        phonecalls[time.time()] = temp
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
                        cryptousage[time.time()] = temp
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

# TODO: Print network communication
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

# TODO: Print monitored intents
print space + "\033[1;48m[Intent receivers]\033[1;m\n" + space + "------------------"

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
    