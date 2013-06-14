#!/usr/bin/python

import argparse
import datetime
import hashlib
import os
import sys

import OpenSSL.crypto
import vobject

def parsedate(s):
	if not s.endswith("Z"):
		raise ValueError("timezone parsing not implemented")
	return datetime.datetime.strptime(s[:-1], "%Y%m%d%H%M%S")

def process_cert(cal, seen, filename):
	with open(filename) as f:
		content = f.read()
	uid = hashlib.sha256(content).hexdigest()
	if uid in seen:
		return
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

def main():
	parser = argparse.ArgumentParser(description='certificate expiry to ical converter')
	parser.add_argument('certificates', metavar="CERTIFICATE", type=str, nargs="+", help="file or directory name to process")
	parser.add_argument('-o', '--output', metavar='FILENAME', type=argparse.FileType("w"), default=sys.stdout, help='store generated ical in given FILENAME instead of stdout')
	args = parser.parse_args()


	seen = set()
	cal = vobject.iCalendar()
	for fname in args.certificates:
		if os.path.isdir(fname):
			for entry in os.listdir(fname):
				process_cert(cal, seen, os.path.join(fname, entry))
		else:
			process_cert(cal, seen, fname)

	args.output.write(cal.serialize())

if __name__ == "__main__":
	main()
