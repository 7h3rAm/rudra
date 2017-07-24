#!/usr/bin/env python

from aayudh import utils, fileutils

from lib.core import config, rudra

import sys
import argparse


def main():
  session = utils.objdict({})
  session.config = utils.objdict({})
  session.config.configfile = None
  session.config.cuckooreport = None
  session.config.inputdir = None
  session.config.inputfiles = None
  session.config.interactive = None
  session.config.nobanner = None
  session.config.noribenreport = None
  session.config.reportsdir = None
  session.config.rescan = None
  session.config.serve = None
  session.config.supportedmimetypes = None
  session.config.verbose = None

  parser = argparse.ArgumentParser(description="Rudra - The destroyer of evil")
  parser.add_argument("-c", "--configfile", dest="configfile", action="store", default=None, help="custom config file (default: ./rudra.conf)")
  parser.add_argument("-f", "--inputfile", dest="inputfile", action="append", default=[], help="file to analyze")
  parser.add_argument("-d", "--inputdir", dest="inputdir", action="append", default=[], help="directory to analyze")
  parser.add_argument("-r", "--reportsdir", dest="reportsdir", action="store", default=None, help="custom reports directory (default: ./reports)")
  parser.add_argument("-i", "--interactive", dest="interactive", action="store_true", default=False, help="invoke interactive mode")
  parser.add_argument("-b", "--nobanner", dest="nobanner", action="store_true", default=False, help="disable banner")
  parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="enable verbose output")
  parser.add_argument("-D", "--reportsdirstruct", dest="reportsdirstruct", action="store_true", default=False, help="retain source-like reports directory structure")
  parser.add_argument("-R", "--rescan", dest="rescan", action="store_true", default=False, help="force rescan for input file")
  parser.add_argument("-C", "--cuckooreport", dest="cuckooreport", action="store", default=None, help="cuckoo json report for input file")
  parser.add_argument("-N", "--noribenreport", dest="noribenreport", action="store", default=None, help="noriben csv report for input file")
  args = parser.parse_args()

  # set user preferred file as config file
  # or use default config file
  # and read config options from it
  if args.configfile:
    configfile = args.configfile
  else:
    configfile = "./rudra.conf"
  configobj = config.Config(configfile)
  session.config = utils.objdict(configobj.read_as_dict())

  if len(args.inputfile) > 0:
    session.config.inputfiles = []
    if len(args.inputfile) > 1:
      for f in args.inputfile:
        if fileutils.is_file(f):
          session.config.inputfiles.append(f)
        else:
          utils.error("%s is not a file!" % f)
    else:
      session.config.inputfiles = args.inputfile

  if len(args.inputdir) > 0:
    session.config.inputfiles = []
    for directory in args.inputdir:
      if fileutils.is_dir(directory):
        session.config.inputfiles += fileutils.file_list(directory, whitelist=session.config.supportedmimetypes)

  # set the reports dir
  if "reportsdir" not in session.config.keys():
    session.config.reportsdir = False
  if args.reportsdir:
    session.config.reportsdir = args.reportsdir

  # enable interactive mode
  if "interactive" not in session.config.keys():
    session.config.interactive = False
  if args.interactive:
    session.config.interactive = args.interactive

  # disable banner if requested
  if "nobanner" not in session.config.keys():
    session.config.nobanner = False
  if args.nobanner:
    session.config.nobanner = args.nobanner

  # default config enables following message types: INFO, WARN and ERROR (program exits on an ERROR)
  # to enable DEBUG messages: activate verbosity
  if "verbose" not in session.config.keys():
    session.config.verbose = False
  if args.verbose:
    session.config.verbose = args.verbose

  # force rescan for input file
  if "reportsdirstruct" not in session.config.keys():
    session.config.reportsdirstruct = False
  if args.reportsdirstruct:
    session.config.reportsdirstruct = args.reportsdirstruct

  # force rescan for input file
  if "rescan" not in session.config.keys():
    session.config.rescan = False
  if args.rescan:
    session.config.rescan = args.rescan

  # use arg as cuckoo report for input file
  if "cuckooreport" not in session.config.keys():
    session.config.cuckooreport = None
  if args.cuckooreport and not args.inputdir:
    session.config.cuckooreport = args.cuckooreport

  # use arg as noriben report for input file
  if "noribenreport" not in session.config.keys():
    session.config.noribenreport = None
  if args.noribenreport and not args.inputdir:
    session.config.noribenreport = args.noribenreport

  r = rudra.Rudra(session=session)


if __name__ == "__main__":
  main()

