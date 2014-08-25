Background
========

DroidBox is developed to offer dynamic analysis of Android applications. The following information is described in the results, generated when analysis is complete:

- Hashes for the analyzed package
- Incoming/outgoing network data
- File read and write operations
- Started services and loaded classes through DexClassLoader
- Information leaks via the network, file and SMS
- Circumvented permissions
- Cryptographic operations performed using Android API
- Listing broadcast receivers
- Sent SMS and phone calls


Additionally, two graphs are generated visualizing the behavior of the package. One showing the temporal order of the operations and the other one being a treemap that can be used to check similarity between analyzed packages.

![Alt text](http://dl.dropbox.com/u/1027328/behaviorsample.png "Behavior graph")


![Alt text](http://dl.dropbox.com/u/1027328/treemapsample.png "Treemap graph")

Setup
======

This is a guide to get DroidBox running. The release has only been tested on Linux and Mac OS. If you do not have the Android SDK, download it from http://developer.android.com/sdk/index.html. The following libraries are required: pylab and matplotlib to provide visualization of the analysis result.

1. Export the path for the SDK tools

```
export PATH=$PATH:/path/to/android-sdk/tools/
export PATH=$PATH:/path/to/android-sdk/platform-tools/
```

2. Download necessary files and uncompress it anywhere

wget http://droidbox.googlecode.com/files/DroidBox411RC.tar.gz

3. Setup a new AVD targeting Android 4.1.2 and choose Nexus 4 as device as well as ARM as CPU type by running:

android 

4. Start the emulator with the new AVD:

./startemu.sh <AVD name>

5. When emulator has booted up, start analyzing samples (please use the absolute path to the apk):

./droidbox.sh <file.apk> <duration in secs (optional)> 
The analysis is currently not automated except for installing and starting packages. Ending the analysis is simply done by pressing Ctrl-C. A package will also be implemented soon to populate the emulator with data prior to performing analysis.
