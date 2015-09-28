# TLS Fingerprinting

These tools are to enable the matching (either on the wire or via pcap),
creation, and export of TLS Fingerprints to other formats.  For futher
information on TLS Fingerprinting please see my [TLS Fingerprinting paper][1]
and [talk resources][2](video link coming soon).

In summary the tools are:

* **FingerprinTLS**: TLS session detection on the wire or PCAP and subsequent fingerprint detetion / creation.

* **Fingerprintout**: Export to other formats such as Suricata/Snort rules, ANSI C Structs, "clean" output and xkeyscore (ok, it's regex)

* **fingerprints.json**: The fingerprint "database" itself.

Please feel free to raise issues and make pull requests to submit code changes, fingerprint submissions, etc.

You can find [me on twitter][3] and [the project on twitter][4] also.


[1]: https://blog.squarelemon.com/tls-fingerprinting/
[2]: https://blog.squarelemon.com/blog/2015/09/25/tls-fingerprinting-resources/
[3]: https://twitter.com/synackpse
[4]: https://twitter.com/FingerprinTLS
