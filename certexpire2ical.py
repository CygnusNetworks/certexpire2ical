#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import fnmatch
import hashlib
import os
import sys

import OpenSSL.crypto
import vobject

__author__ = "Helmut Grohne"
__copyright__ = "Cygnus Networks GmbH"
__license__ = "proprietary"
__version__ = "0.2"
__maintainer__ = "Cygnus Networks GmbH"
__email__ = "info@cygnusnetworks.de"
__status__ = "Beta"


class CertNotAdded(Exception):
	pass


def parsedate(s):
	if not s.endswith("Z"):
		raise ValueError("timezone parsing not implemented")
	return datetime.datetime.strptime(s[:-1], "%Y%m%d%H%M%S")


class Cert2Cal(object):  # pylint:disable=R0903
	def __init__(self, notify, expire):
		self.cal = vobject.iCalendar()
		self.seen = set()
		self.notify = notify
		self.expire = expire
		self.now = datetime.datetime.now()

	def add_cert(self, filename):
		try:
			with open(filename) as f:
				content = f.read()
		except IOError as exc:
			raise CertNotAdded("failed to read %s: %s" % (filename, exc))
		uid = hashlib.sha256(content.encode('utf-8')).hexdigest()  # pylint:disable=E1101
		if uid in self.seen:
			return
		self.seen.add(uid)
		try:
			x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
		except OpenSSL.crypto.Error as err:
			raise CertNotAdded("failed to parse %s with openssl: %r" % (filename, err))
		expires = parsedate(x509.get_notAfter().decode('ascii'))
		cn = x509.get_subject().commonName

		if expires > self.now:
			vev = self.cal.add("vevent")
			vev.add("uid").value = uid
			vev.add("summary").value = "Expire CN:%s" % cn
			vev.add("description").value = "Filename %s" % filename
			vev.add("dtend").value = expires
			vev.add("dtstart").value = expires
			alarm = vev.add("valarm")
			alarm.add("uid").value = "%s-alarm-notify" % uid
			alarm.add("trigger").value = expires - self.notify
			alarm.add("action").value = "DISPLAY"
			alarm.add("description").value = "Notify"

			alarm = vev.add("valarm")
			alarm.add("uid").value = "%s-alarm-expire" % uid
			alarm.add("trigger").value = expires - self.expire
			alarm.add("action").value = "DISPLAY"
			alarm.add("description").value = "Notify"
		else:
			pass

	def __str__(self):
		return self.cal.serialize()


def days(s):
	return datetime.timedelta(days=int(s))


def main():
	parser = argparse.ArgumentParser(description='certificate expiry to ical converter')
	parser.add_argument('certificates', metavar="CERTIFICATE", type=str, nargs="+", help="file or directory name to process")
	parser.add_argument('-o', '--output', metavar='FILENAME', type=argparse.FileType("w"), default=sys.stdout, help='store generated ical in given FILENAME instead of stdout')
	parser.add_argument('-n', '--notify', metavar='DAYS', type=days, default=days(14), help="time before first notification should be triggered")
	parser.add_argument('-e', '--expire', metavar='DAYS', type=days, default=days(1), help="time before second notification should be triggered")
	parser.add_argument('-v', '--verbose', action='count', help='increase debug level')
	parser.add_argument('-p', '--pattern', type=str, default='*.crt', help='when processing directories only consider matching files (default: %(default)s)')
	parser.add_argument('-s', '--subdir', type=str, default='keys', help='only processing subdirs ending with (default: %(default)s) in path name')
	args = parser.parse_args()

	cert2cal = Cert2Cal(args.notify, args.expire)
	for fname in args.certificates:
		if os.path.isdir(fname):
			for directory, dirpath, filenames in os.walk(fname):  # pylint:disable=W0612
				if not directory.endswith("/" + args.subdir):
					continue
				for entry in filenames:
					filename = os.path.join(directory, entry)
					if not fnmatch.fnmatch(entry, args.pattern):
						continue
					try:
						cert2cal.add_cert(filename)
					except CertNotAdded as err:
						print(err)
		else:
			try:
				cert2cal.add_cert(fname)
			except CertNotAdded as err:
				print(err)

	args.output.write(str(cert2cal))


if __name__ == "__main__":
	main()
