#!/usr/bin/env python

from aayudh import fileutils, apis
import argparse
import base64

b64 = False


def pb_create(filename):
  # http://pastebin.com/faq#9
  # 512kB limit per paste
  if fileutils.is_file(filename):
    with open(filename) as fo:
      pastedata = fo.read()
      if b64:
        pastedata = base64.b64encode(pastedata)
    res = apis.pastebin_create(pastedata)
    if res.success:
      return res.pasteurl
  return None

def pb_retrieve(pasteid):
  res = apis.pastebin_retrieve(pasteid)
  if res.success:
    if b64:
      return base64.b64decode(res.pastedata)
    return res.pastedata
  return None

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Pastebin Client w/ B64 - Rudra")
  parser.add_argument("-b", action="store_true", dest="b64", default=False)
  group = parser.add_mutually_exclusive_group()
  group.add_argument("-c", action="store", dest="create")
  group.add_argument("-r", action="store", dest="retrieve")
  args = parser.parse_args()

  if args.b64:
    b64 = True

  if args.create:
    print pb_create(args.create)
  elif args.retrieve:
    filedata = pb_retrieve(args.retrieve)
    if filedata:
      with open("file.vxe", "wb") as fo:
        fo.write(filedata)
      print "Saved paste data to file.vxe"
    else:
      print "No paste found with id: %s" % (args.retrieve)
