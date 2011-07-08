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
from threading import Thread

sendsms = {}
phonecalls = {}
dataleaks = {}
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
        while 1 and not self.stop:
            sign = signs[counter % len(signs)]
            sys.stdout.write(":[%s] Collected %s sandbox logs\r" % (sign, str(self.logs)))
            sys.stdout.flush()
            time.sleep(0.5)
            counter = counter + 1

print '\nDroidBox\n'
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
                jsonStr = taintlog[1].strip()
                data = json.loads(jsonStr)
                if data.has_key('SendSMS') and jsonStr not in sendsms.values():
                    sendsms[time.time()] = jsonStr
                elif data.has_key('PhoneCall') and jsonStr not in phonecalls.values():
                    phonecalls[time.time()] = jsonStr
                elif data.has_key('DataLeak') and jsonStr not in dataleaks.values():
                    dataleaks[time.time()] = jsonStr
                elif data.has_key('CryptoUsage') and jsonStr not in cryptousage.values():
                    cryptousage[time.time()] = jsonStr
                else:
                    continue
                count.increaseCount()
            except ValueError:
                pass
    except KeyboardInterrupt:
        # Clear screen for analysis report
        curses.setupterm()
        sys.stdout.write(curses.tigetstr("clear"))
        sys.stdout.flush()
        # Wait for counting thread to stop
        count.stopCounting()
        count.join()
        break

# Print crypto API usage
keys = cryptousage.keys()
keys.sort()
print "\nUsage of cryptography API\n========================="
for key in keys:
    data = json.loads(cryptousage[key])
    try:
        if data['CryptoUsage']['operation'] == 'keyalgo':
            print 'Key: { ' + data['CryptoUsage']['key'] + ' }'
            print 'Algorithm: ' + data['CryptoUsage']['algorithm'] + '\n'
        else:
            print 'Action: ' + data['CryptoUsage']['operation']
            print 'Algorithm: ' + data['CryptoUsage']['algorithm']
            print 'Data: ' + data['CryptoUsage']['data'] + '\n'
    except ValueError:
        pass

# Print data leaks
keys = dataleaks.keys()
keys.sort()
print "\nInformation leaks\n================="
for key in keys:
    data = json.loads(dataleaks[key])
    try:
        print 'Sink: ' + data['DataLeak']['sink']
        print 'Destination host: ' + data['DataLeak']['desthost']
        print 'Destination port: ' + data['DataLeak']['destport']
        print 'Taint tag: ' + tags[int(data['DataLeak']['tag'], 16)]
        print 'Data: ' + data['DataLeak']['data'] + '\n'
    except ValueError:
        pass

# Print sent SMSs
keys = sendsms.keys()
keys.sort()
print "\nAttempts to send SMS\n===================="
for key in keys:
    data = json.loads(sendsms[key])
    try:
        print 'Number: ' + data['SendSMS']['number']
        print 'Message: ' + data['SendSMS']['message'] + '\n'
    except ValueError:
        pass
        
# Print phone calls
keys = phonecalls.keys()
keys.sort()
print "\nPhone calls made\n================"
for key in keys:
    data = json.loads(phonecalls[key])
    try:
        print 'Number: ' + data['PhoneCall']['number'] + '\n'
    except ValueError:
        pass
            