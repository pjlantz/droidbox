DroidBox4.1.1 is a framework for analyzing automatically Android applications. It uses a modified version of the Android emulator 4.1.1_rc6 enabling to track Android applications' activity, i.e., tainted data leaked out, SMS sent, network communications, etc. It is composed of two folds: one fold on the guest machine (Android emulator) that tracks the Android application's activity and sends the corresponding DroidBox logs through ADB to the host machine and the other fold on the host machine that parses the ADB log to extract the DroidBox log.

Step 1: Get the Android source code

Droidbox4.1.1 uses a modified version of Android 4.1.1_rc6. In order to modify the Android firmware, you first need to get the Android source 4.1.1_rc6. Please follow the instructions at http://source.android.com/ for getting the Android source code. 

In summary, the list of instructions are as follows:

$ mkdir -p ~/droidbox4.1.1/emulator
$ cd ~/droidbox4.1.1/emulator
$ repo init -u https://android.googlesource.com/platform/manifest -b android-4.1.1_r6
$ repo sync

Now, you should get the Android source code.

Step 2: Apply the DroidBox patches

In order to incorporate the DroidBox into the Android emulator, you need to apply the Droidbox patches to the Android source code.

$ cd ~/droidbox4.1.1/emulator/dalvik
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/dalvik.patch

$ cd ~/droidbox4.1.1/emulator/libcore
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/libcore.patch

$ cd ~/droidbox4.1.1/emulator/system/core
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/system_core.patch

$ cd ~/droidbox4.1.1/emulator/system/vold
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/system_vold.patch

$ cd ~/droidbox4.1.1/emulator/frameworks/base
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/frameworks/base.patch

$ cd ~/droidbox4.1.1/emulator/frameworks/native
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/frameworks/native.patch

$ cd ~/droidbox4.1.1/emulator/device/samsung/crespo.patch
$ git am --droidbox4.1.1 < ~/droidbox4.1.1/patches/device_samsung_crespo.patch

You also need to create the file "~/droidbox4.1.1/emulator/buildspec.mk" with the following content so as to integrate the taint data tracking

# Enable core taint tracking logic (always add this)
WITH_TAINT_TRACKING := true

# Enable taint tracking for ODEX files (always add this)
WITH_TAINT_ODEX := true

# Enable taint tracking in the "fast" (aka ASM) interpreter (recommended)
WITH_TAINT_FAST := true

# Enable additional output for tracking JNI usage (not recommended)
#TAINT_JNI_LOG := true

# Enable byte-granularity tracking for IPC parcels
#WITH_TAINT_BYTE_PARCEL := true

Step 3: Compile the modified Android source code

$ cd ~/droidbox4.1.1/emulator
$ . build/envsetup.sh
$ lunch 1
$ make -j4

Step 4: Launch the new emulator

$ emulator

Step 5: Analyze an Android application

$ cd ~/droidbox4.1.1
$ bash droidbox.sh ~/Android.APK
