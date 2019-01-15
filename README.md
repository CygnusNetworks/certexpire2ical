# certexpire2ical #

# SSL Cert Expiration calendar tool (certexpire2ical)

This tool parses single ssl certificates or a complete directory and subdirs and searches for X509 SSL Certificates and extracts certificate expiration times from the ssl certs.
As output it create a calendar data file (in ics File format), which can be added to calendar programs (like Apple iCal, iOS or Android calenders) to get a overview and alerts about expiring certificates.

## Requirements ##
 
 * Python 3
 * vobject
 * pyOpenSSL

## Examples

Get certificate expiry of one cert in a textfile
```
./certexpire2ical.py thawte/SSL123_CA_Bundle.pem.txt                                                                                                                       master↑152| 
BEGIN:VCALENDAR
VERSION:2.0
...
```

Parse through subdirs and find all crt files and generate a file containing all cert expiry dates.
```
find . -name *.crt| xargs ./certexpire2ical.py -v -o all.ics
```
