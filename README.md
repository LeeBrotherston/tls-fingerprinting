# TLS Fingerprinting [![Build Status](https://travis-ci.org/LeeBrotherston/tls-fingerprinting.svg?branch=master)](https://travis-ci.org/LeeBrotherston/tls-fingerprinting) <img src="https://www.toolswatch.org/badges/arsenal/2016.svg" />

These tools are to enable the matching (either on the wire or via pcap),
creation, and export of TLS Fingerprints to other formats.  For futher
information on TLS Fingerprinting:

* My [TLS Fingerprinting paper][1],
* My [Derbycon Talk][2], and [slides][3] on the topic.
* My [SecTorCA Talk][4], and [slides][5] on the topic.
* TLS Fingerprinting Discussion on [Brakeing Down Security Podcast][6]
* Quick [demo of tor detection][7] with FingerPrinTLS

In summary the tools are:

* **FingerprinTLS**: TLS session detection on the wire or PCAP and subsequent fingerprint detetion / creation.

* **Fingerprintout**: Export to other formats such as Suricata/Snort rules, ANSI C Structs, "clean" output and xkeyscore (ok, it's regex).  NOTE:  Because of a lack of flexibility in the suricata/snort rules language, this is currently less accurate than using FingerprinTLS to detect fingerprints and so may require tuning.

* **fingerprints.json**: The fingerprint "database" itself.

Please feel free to raise issues and make pull requests to submit code changes, fingerprint submissions, etc.

You can find [me on twitter][8] and [the project on twitter][9] also.


[1]: https://blog.squarelemon.com/tls-fingerprinting/
[2]: https://www.youtube.com/watch?v=XX0FRAy2Mec
[3]: http://www.slideshare.net/LeeBrotherston/tls-fingerprinting-stealthier-attacking-smarter-defending-derbycon
[4]: http://2015.video.sector.ca/video/144175700 
[5]: http://www.slideshare.net/LeeBrotherston/tls-fingerprinting-sectorca-edition
[6]: http://brakeingsecurity.com/2015-007-fingerprintls-profiling-application-with-lee-brotherston
[7]: https://www.youtube.com/watch?v=ifODVQ3hBVs
[8]: https://twitter.com/synackpse
[9]: https://twitter.com/FingerprinTLS
