from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class extractoverlay(PluginInterface):
  name = "extractoverlay"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Extract overlay data into report directory"
    self.details.mimetypes = ["application/x-dosexec"]
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "19/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      if report.pe.static.overlay and report.pe.static.overlay.size:
        with open(report.meta.filename, "rb") as fo:
          filedata = fo.read()
        fileutils.file_save(filename="%s/%s.overlay" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data=filedata[report.pe.static.overlay.offset:report.pe.static.overlay.offset+report.pe.static.overlay.size], mode="w" if report.pe.static.overlay.mimetype and "text" in report.pe.static.overlay.mimetype else "wb")

    return


Manager().register_plugin(extractoverlay)

