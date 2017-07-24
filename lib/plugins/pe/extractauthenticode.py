from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class extractauthenticode(PluginInterface):
  name = "extractauthenticode"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Extract authenticode data into report directory"
    self.details.mimetypes = ["application/x-dosexec"]
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "19/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      if report.pe.static.authenticode:
        if report.pe.static.authenticode.offset > 0 and report.pe.static.authenticode.size > 0:
          with open(report.meta.filename, "rb") as fo:
            filedata = fo.read()
          authenticoderaw = filedata[report.pe.static.authenticode.offset:report.pe.static.authenticode.offset+report.pe.static.authenticode.size]
          mtype = utils.data_mimetype(authenticoderaw)
          mode = "w" if mtype and "text" in mtype  else "wb"
          fileutils.file_save(filename="%s/%s.der" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data=authenticoderaw, mode=mode)

    return


Manager().register_plugin(extractauthenticode)

