certexpire2ical
===============

X.509 SSL Cert Expiration to iCal Tool

The tool parses single certificates or a complete directory and subdirs and searches for X509 Certificates. All found files are parsed and the expiration date (not after) is extracted.

A ICS (Apple Calendar File) is created containing a list of certificate expiry dates including a configurable alert event n days (n defaults to 30) before cert expiration.
