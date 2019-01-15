# certexpire2ical #

## X.509 SSL Cert Expiration to iCal Tool ##

The tool parses single certificates or a complete directory and subdirs and searches for X509 Certificates. All found files are parsed and the expiration date (not after) is extracted.

A Apple Calendar File (ics) is created containing a list of certificate expiry dates including a two alert events n days (n defaults to one and 14 days) before cert expiration.

## Requirements ##

 * vobject
 * pyOpenSSL