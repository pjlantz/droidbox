import sys, time
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice

device = MonkeyRunner.waitForConnection()
device.installPackage(sys.argv[1])
package = sys.argv[2]
activity = sys.argv[3]

# sets the name of the component to start
runComponent = package + '/' + activity
print "Running: " + runComponent
# Runs the component
device.startActivity(component=runComponent)

time.sleep(5)
# Takes a screenshot
print "Taking snapshot"
result = device.takeSnapshot()
# Writes the screenshot to a file
result.writeToFile('shot1.png','png')
