#!/usr/bin/python

import datetime
import sys

import OpenSSL.crypto
import vobject

def parsedate(s):
	if not s.endswith("Z"):
		raise ValueError("timezone parsing not implemented")
	return datetime.datetime.strptime(s[:-1], "%Y%m%d%H%M%S")

def main():
	cal = vobject.iCalendar()
	advance = datetime.timedelta(weeks=1)
	for fname in sys.argv[1:]:
		with open(fname) as f:
			content = f.read()
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
		expires = parsedate(x509.get_notAfter())
		cn = x509.get_subject().commonName

		vev = cal.add("vtodo")
		vev.add("summary").value = "Renew certificate %s" % cn
		vev.add("status").value = "NEEDS-ACTION"
		vev.add("due").value = expires
		vev.add("dtstart").value = expires - advance
	sys.stdout.write(cal.serialize())

if __name__ == "__main__":
	main()
