AWS KMS CA
----------

*WARNING* this is not somehting you should use unless you know *exactly* what you are doing, and why. 

Tools for assembling an X.509 certificate and sending it to an AWS KMS asymmetric CMK for signing
Support only for P256 and P384 key specs currently.
Examples of how to build a self-signed root Certificate Authority, a Server leaf certificate, and a Client leaf certificate are in the examples directory.

Resources
---------
https://tools.ietf.org/html/rfc5280
https://tools.ietf.org/html/rfc5480

https://cipherious.wordpress.com/2013/05/13/constructing-an-x-509-certificate-using-asn-1/

