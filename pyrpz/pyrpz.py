#!/usr/bin/env python
# Copyright 2020 Liam Nolan

"""
A simple tool to turn domain lists into rpz zones
https://tools.ietf.org/id/draft-vixie-dnsop-dns-rpz-00.html
"""

import sys
import datetime
import urllib
from urllib import request
import argparse
import validators

class Logger:
    @staticmethod
    def log(log):
        entry = "%s\n" % log
        sys.stderr.write(entry)

class DataList:
    """
    Abstract class for data
    """
    def __init__(self, data=None):
        self.setData(data)
        self._index = 0

    def __iter__(self):
        return self

    def __next__(self):
        i = self._index
        self._index += 1
        try:
            return self.data[i]
        except IndexError:
            raise StopIteration

    def setData(self, data):
        self.data = data

    def getData(self):
        return self.data

class DomainList(DataList):
    """
    Class for validating a list of domain names and removing comments
    """

    def setData(self, data=None):
        self.data = self._cleanList(data)
        return self.data

    def getData(self):
        return self.data.copy()

    @staticmethod
    def _cleanList(lst):
        # return a list of domain names only
        valid_domains = []
        for line in lst:
            l = line.lstrip().rstrip()
            if isinstance(l, bytes):
                l = l.decode()
            if validators.domain(l):
                valid_domains.append(l)
        return valid_domains

class RPZZone(DataList):
    """
    Class that constructs an rpz zone file
    """
    actions = {
        "default":"CNAME .",
        "NXDOMAIN":"CNAME .",
        "NODATA":"CNAME *.",
        "PASSTHRU":"CNAME rpz-passthru.",
        "DROP":"CNAME rpz-drop.",
        "TCP-Only":"CNAME rpz-tcp-only."}
    def __init__(self,
                 data,
                 name="default.pyrpz",
                 serial="1",
                 refresh="3600",
                 retry="1800",
                 expire="604800",
                 ttl="3600",
                 action="default",
                 nameserver="127.0.0.1"):

        super().__init__(data)
        self.name = name
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.ttl = ttl
        self.action = action
        self.setData(data)
        self.nameserver = nameserver
        self.setZone(self.constructZone())

    def __str__(self):
        return str(self.getZone())

    def getZone(self):
        return self.zone

    def setZone(self, data):
        self.zone = data

    def getData(self):
        return self.data

    def setData(self, data):
        assert isinstance(data, DomainList), "data must be a DomainList"
        self.data = data

    def constructRecord(self, entry, action="default"):
        r = "%s.%s.    %s" % (str(entry), self.name, self.actions[action])
        rs = "*.%s.%s.   %s" % (str(entry), self.name, self.actions[action])
        if entry[0:2] == "*.":
            return r
        return "%s\n%s" % (r, rs)

    def constructZone(self):
        s = self
        ttl = "$TTL %s" % self.ttl
        #origin = "$ORIGIN %s" % self.name
        soa = "@         SOA          %s.    root.%s (%s %s %s %s %s)" % (
            s.name, s.name, s.serial, s.refresh, s.retry, s.expire, s.ttl)
        nsr = "@         NS           ns.%s." % s.name
        nsa = "ns.%s.    IN     A     %s" % (s.name, s.nameserver)
        records = []
        records.extend([ttl, soa, nsr, nsa])
        for domain in self.getData():
            records.append(self.constructRecord(domain, action=self.action))
        zone = "\n".join(records)

        return zone

class PyRPZ:
    """
    Main control loop
    """
    def __init__(self):
        self.open_files = []
        self.ap = argparse.ArgumentParser(
            "PyRPZ",
            "A simple Python RPZ constructor.")
        self.args = None
        self.f = None
        self.w = None
    def setupArgs(self):
        # argparse

        i = self.ap.add_mutually_exclusive_group(required=True)
        i.add_argument(
            "--url",
            action="store",
            help="URL pointing to a newline delimited domain list.")
        i.add_argument(
            "--infile",
            action="store",
            help="File path pointing to a newline delimited domain list.")
        # policy options
        polop = self.ap.add_argument_group(title="RPZ Policy Configuration")
        polop.add_argument(
            "--action",
            action="store",
            help="RPZ policy action",
            choices=list(RPZZone.actions.keys()),
            default="default")
        # SOA options
        soaop = self.ap.add_argument_group(title="SOA", description="SOA Configuration Options")
        soaop.add_argument(
            "--mmname",
            action="store",
            help="Primary master name server",
            default="pyrpz.rpz")
        soaop.add_argument(
            "--serial",
            action="store",
            type=int,
            help="RPZ Zone serial number. Omit to use the date as a serial.",
            default=int(datetime.datetime.today().strftime("%Y%m%d%H")))
        soaop.add_argument(
            "--refresh",
            action="store",
            type=int,
            help="RPZ Zone SOA record update interval.",
            default=86400)
        soaop.add_argument(
            "--retry",
            action="store",
            type=int,
            help="Secondary name server SOA transfer retry interval. Must be < --refresh.",
            default=7200)
        soaop.add_argument(
            "--expire",
            action="store",
            type=int,
            help="Zone expiry, must be larger than --refresh and --retry.",
            default=3600000)
        soaop.add_argument(
            "--ttl",
            action="store",
            type=int,
            help="Negative Cache TTL.",
            default=172800)
        soaop.add_argument(
            "--nameserver",
            action="store",
            type=str,
            help="Value to store as the A record of the zones NS, defaults to localhost.",
            default="127.0.0.1")

        of = self.ap.add_mutually_exclusive_group()
        of.add_argument(
            "--outfile",
            action="store",
            help="File path to output RPZ zone.")
        of.add_argument(
            "--stdout",
            action="store_true",
            help="Send RPZ zone to stdout.",
            default=True)

        args = self.ap.parse_args()
        if args.retry > args.refresh:
            msg = "--retry must be smaller than --refresh"
            self.ap.error(msg)
        if (args.expire < args.retry) or (args.expire < args.refresh):
            msg = "--expire must be larger than --retry and --refresh"
            self.ap.error(msg)
        if args.outfile:  # reset default when --outfile is specified
            args.stdout = False
        if not validators.ip_address.ipv4(args.nameserver):
            self.ap.error("--nameserver-addr must be a valid ipv4 address")
        self.args = args

    def run(self):
        self.setupArgs()
        args = self.args
        rpz_zone = None
        data = None

        if args.url:  # --url
            if not validators.url(args.url):
                Logger.log("--url requires a valid URL")
                sys.exit(1)
            try:
                page = urllib.request.urlopen(args.url)
            except urllib.request.URLError as ue:
                err = "%s %s" % (str(ue.code), ue.reason)
                Logger.log(err)
            if not page:
                Logger.log("URL Failure.")
                sys.exit(1)
            data = DomainList(page)

        if args.infile:  # --infile
            self.f = open(args.infile, "r")
            self.open_files.append(self.f)
            if not self.f:
                Logger.log("File Failure.")
                sys.exit(1)
            data = DomainList(self.f)

        if not data:
            Logger.log("No valid domains found in URL.")
            sys.exit(1)
        rpz_zone = RPZZone(data, name=args.mmname, serial=args.ttl,
                           refresh=args.refresh, retry=args.retry,
                           expire=args.expire, ttl=args.ttl,
                           action=args.action, nameserver=args.nameserver)

        # output
        if args.stdout:
            sys.stdout.write(str(rpz_zone))
        if args.outfile:
            try:
                self.w = open(args.outfile, mode="x").write(str(rpz_zone))
            except FileExistsError:
                Logger.log("File exists.")
                sys.exit(1)
            self.open_files.append(self.w)

        sys.exit(0)

    def close_files(self):
        for f in self.open_files:
            try:
                f.close()
                self.open_files.remove(f)
            except Exception as error:
                self.open_files.remove(f)
                Logger.log(error.args)
        return True

