#!/usr/local/bin/python
import sys
import json
#import time

while True:
    s = sys.stdin.readline()
    if not s:
        break
    s2 = s.split("TaintLog:")
    if len(s2) > 1:
        try:
            data = json.loads(s2[1].strip())
            if data.has_key('SendSMS'):
                print '\nSending SMS\n==========='
                print 'Number: ' + data['SendSMS']['number']
                print 'Message: ' + data['SendSMS']['message'] + '\n'
            if data.has_key('PhoneCall'):
                print '\nPhone call\n============='
                print 'Number: ' + data['PhoneCall']['number'] + '\n'
        except ValueError:
            pass
