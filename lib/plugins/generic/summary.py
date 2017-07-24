from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class summary(PluginInterface):
  name = "summary"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Display a summary for each file"
    self.details.mimetypes = None
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "15/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if hasattr(report, "meta"):
      borderflag = False
      headerflag = False
      padwidth = 1

      # show file metainfo
      summarytab = PrettyTable(["Attribute", "Value"])
      summarytab.border = borderflag
      summarytab.header = headerflag
      summarytab.padding_width = padwidth
      summarytab.align["Attribute"] = "l"
      summarytab.align["Value"] = "l"

      summarytab.add_row(["File", report.meta.filebasename])
      summarytab.add_row(["Location", report.meta.filedirname])
      summarytab.add_row(["MIMEType", report.meta.filemimetype])
      summarytab.add_row(["Magic", report.meta.filemagic])
      summarytab.add_row(["Size", report.meta.filesize])
      summarytab.add_row(["Minsize", "%s (%s%%)" % (report.meta.fileminsize, report.meta.filecompressionratio) if report.meta.fileminsize and report.meta.filecompressionratio else "None"])
      summarytab.add_row(["Entropy", "%s (%s)" % (report.meta.fileentropy, report.meta.fileentropycategory) if report.meta.fileentropy and report.meta.fileentropycategory else "None"])

      hashtab = PrettyTable(["Hash", "Value"])
      hashtab.border = False
      hashtab.header = False
      hashtab.padding_width = 1
      hashtab.align["Hash"] = "l"
      hashtab.align["Value"] = "l"
      for hashfunc in report.meta.hashes:
        if hashfunc != "sha512":
          hashtab.add_row([hashfunc.upper(), report.meta.hashes[hashfunc]])
      summarytab.add_row(["Hashes", hashtab.get_string()])

      if report.meta.subfiles and len(report.meta.subfiles):
        subfilestab = PrettyTable(["Attribute", "Value"])
        subfilestab.border = False
        subfilestab.header = False
        subfilestab.padding_width = 1
        subfilestab.align["Attribute"] = "l"
        subfilestab.align["Value"] = "l"
        for subfile in report.meta.subfiles:
          if subfile["offset"] and subfile["offset"] > 0 and subfile["size"] and subfile["size"] > 0:
            subfilestab.add_row(["Description", subfile["description"]])
            subfilestab.add_row(["SHA256", subfile["hashes"]["sha256"]])
            subfilestab.add_row(["MIMEType", subfile["mimetype"]])
            subfilestab.add_row(["Offset:Size", "%d:%d" % (subfile["offset"], subfile["size"])])
            subfilestab.add_row(["", ""])
        summarytab.add_row(["Subfiles", subfilestab.get_string()])

      result = summarytab.get_string()
      if result != "":
        print "\nMeta Information:\n%s" % result


Manager().register_plugin(summary)

