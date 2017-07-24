from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class extractvisual(PluginInterface):
  name = "extractvisual"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Extract all visual content into report directory"
    self.details.mimetypes = None
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "23/MAR/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if report.misc.config.enablefilevisualization and report.meta.visual:
      fileutils.file_save(filename="%s/%s.pnggray" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data=utils.from_base64(report.meta.visual.pnggray), mode="wb")
      fileutils.file_save(filename="%s/%s.pngrgb" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data=utils.from_base64(report.meta.visual.pngrgb), mode="wb")
      fileutils.file_save(filename="%s/%s.bfh" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data=report.meta.visual.bytefreqhistogram, mode="wb")
      if report.meta.visual.identicon:
        fileutils.file_save(filename="%s/%s.identicon" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data=utils.from_base64(report.meta.visual.identicon), mode="wb")

    return


Manager().register_plugin(extractvisual)

