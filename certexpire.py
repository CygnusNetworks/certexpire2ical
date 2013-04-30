#!/usr/bin/python

import datetime
import hashlib
import sys

import OpenSSL.crypto
import vobject

def parsedate(s):
	if not s.endswith("Z"):
		raise ValueError("timezone parsing not implemented")
	return datetime.datetime.strptime(s[:-1], "%Y%m%d%H%M%S")

def main():
	seen = set()
	cal = vobject.iCalendar()
	for fname in sys.argv[1:]:
		with open(fname) as f:
			content = f.read()
		uid = hashlib.sha256(content).hexdigest()
		if uid in seen:
			continue
		seen.add(uid)
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
		expires = parsedate(x509.get_notAfter())
		cn = x509.get_subject().commonName

		vev = cal.add("vevent")
		vev.add("uid").value = uid
		vev.add("summary").value = "Renew certificate %s" % cn
		vev.add("dtend").value = expires
		vev.add("dtstart").value = expires
		alarm = vev.add("valarm")
		alarm.add("uid").value = "%s-alarm" % uid
		alarm.add("trigger").value = -datetime.timedelta(weeks=3)
	sys.stdout.write(cal.serialize())

if __name__ == "__main__":
	main()
