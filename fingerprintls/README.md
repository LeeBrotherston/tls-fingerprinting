# FingerPrinTLS <img src="https://www.toolswatch.org/badges/arsenal/2016.svg" />

FingerPrinTLS is the main tool in this [tls-fingerprinting][1] collection, it is the tool which performs the actual analysis of packets which are collected either via live packet sniffing or via pcaps loaded on the commandline.

FingerPrinTLS requires libpcap, which is included in most modern distributions.  If they do not include this library then it will almost certainly be in the relevent package management system.

This tool is tested on OS X, FreeBSD, and Linux; using GCC and Clang as compilers.  Current build status is: [![Build Status](https://travis-ci.org/LeeBrotherston/tls-fingerprinting.svg?branch=master)](https://travis-ci.org/LeeBrotherston/tls-fingerprinting)

The commandline switches, as ridiculous as some of them are, are:
```
-h                Display help
-i <interface>    Operate in live packetsniffing mode, capturing traffic from <interface>
-p <pcap file>    Operate in filesystem mode, reading packets from specified pcap file
-P <pcap file>    Save client hello packets to specified pcap file for any unknown fingerprints.  Useful for when creating new fingerprints and analysing unknown traffic.
-j <json file>    Location to save automatically generated fingerprint data (json format).  This can by used my the [FingerPrintOut][2] script.
-l <log file>     Location to save "log" file (json format) which can be parsed by [parselog][2]
-d                Show reasons for discarded packets (post BPF).  Typically this is because a packet is identified as malformed or not really TLS mid-processing.
-f <fpdb>         Load the (binary) FingerPrint Database from the specified location
-u <uid>          Drop privileges to specified UID (not username).  This allows the use of this tool without running as root (although it will need to be started as root in order to obtain permissions to sniff live interfaces)
```

# Installing

FingerPrinTLS is provided with a make file which I have been testing on:

* Mac OS X
* Linux
* FreeBSD

Using:

* gcc
* clang

Other combinations may well work, just I have not tried them yet.

If for some reason you cannot use makefiles to build software on your system the compiler commandline should look something like:

```
$compiler fingerprintls.c -o fingerprintls -lpcap
``` 


[1]: https://blog.squarelemon.com/tls-fingerprinting/
[2]: https://github.com/LeeBrotherston/tls-fingerprinting/tree/master/scripts
