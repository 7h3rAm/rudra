from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class extractstrings(PluginInterface):
  name = "extractstrings"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Extract ascii and unicode strings into report directory"
    self.details.mimetypes = ["application/x-dosexec"]
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "19/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      if report.pe.static.strings.ascii and len(report.pe.static.strings.ascii):
        data = []
        for s in report.pe.static.strings.ascii:
          data.append(s["string"])
        fileutils.file_save(filename="%s/%s.ascii.strings" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data="\n".join(data), mode="w")

      if report.pe.static.strings.unicode and len(report.pe.static.strings.unicode):
        data = []
        for s in report.pe.static.strings.unicode:
          data.append(s["string"])
        fileutils.file_save(filename="%s/%s.unicode.strings" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data="\n".join(data), mode="w")

    return


Manager().register_plugin(extractstrings)

