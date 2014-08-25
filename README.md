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

![Alt text](http://dl.dropbox.com/u/1027328/behaviorsample.png "Optional Title")

