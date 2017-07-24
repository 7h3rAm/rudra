from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class extractsubfiles(PluginInterface):
  name = "extractsubfiles"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Extract all subfiles into report directory"
    self.details.mimetypes = None
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "19/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if report.meta.subfiles and len(report.meta.subfiles) > 1:
      with open(report.meta.filename, "rb") as fo:
        filedata = fo.read()
      for entry in report.meta.subfiles:
        if entry["offset"] > 0 and entry["size"] and entry["size"] > 0:
          fileutils.file_save(filename="%s/%s_%s" % (report.misc.config.currreportpath, report.misc.config.currreportfile, entry["hashes"]["sha256"]), data=filedata[entry["offset"]:entry["offset"]+entry["size"]], mode="w" if "text" in entry["mimetype"] else "wb")
    return


Manager().register_plugin(extractsubfiles)

