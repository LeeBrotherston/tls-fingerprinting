# TLS Fingerprinting additional scripts

* **fingerprintout.py** - Used to convert the fingerprints.json file to various other formats.  Mostly useful using "-c" to "cleanse".  That is, remove servernames to protect privacy and flag up duplicate fingerprints.
* **parselog.py** - A log tailer for humans reading the output from fingerprintls.  Makes it pretty instead of json.
