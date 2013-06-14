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

class Cert2Cal(object):
	def __init__(self, trigger_delta):
		"""
		@type trigger_delta: datetime.timedelta
		@param trigger_delta: how much time before expiry should the event trigger?
		"""
		self.cal = vobject.iCalendar()
		self.seen = set()
		self.trigger_delta = trigger_delta

	def add_cert(self, filename):
		with open(filename) as f:
			content = f.read()
		uid = hashlib.sha256(content).hexdigest()
		if uid in self.seen:
			return
		self.seen.add(uid)
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
		expires = parsedate(x509.get_notAfter())
		cn = x509.get_subject().commonName

		vev = self.cal.add("vevent")
		vev.add("uid").value = uid
		vev.add("summary").value = "Renew certificate %s" % cn
		vev.add("dtend").value = expires
		vev.add("dtstart").value = expires
		alarm = vev.add("valarm")
		alarm.add("uid").value = "%s-alarm" % uid
		alarm.add("trigger").value = -self.trigger_delta

	def __str__(self):
		return self.cal.serialize()

def days(s):
	return datetime.timedelta(days=int(s))

def main():
	parser = argparse.ArgumentParser(description='certificate expiry to ical converter')
	parser.add_argument('certificates', metavar="CERTIFICATE", type=str, nargs="+", help="file or directory name to process")
	parser.add_argument('-o', '--output', metavar='FILENAME', type=argparse.FileType("w"), default=sys.stdout, help='store generated ical in given FILENAME instead of stdout')
	parser.add_argument('-d', '--duration', metavar='DAYS', type=days, default=days(21), help="how much time before expiry should the events trigger")
	args = parser.parse_args()


	cert2cal = Cert2Cal(args.duration)
	for fname in args.certificates:
		if os.path.isdir(fname):
			for entry in os.listdir(fname):
				cert2cal.add_cert(os.path.join(fname, entry))
		else:
			cert2cal.add_cert(fname)

	args.output.write(str(cert2cal))

if __name__ == "__main__":
	main()
