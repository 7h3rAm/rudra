from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class template(PluginInterface):
  name = "template"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Plugin template to be used for creating new plugins"
    self.details.mimetypes = ["application/x-dosexec"]
    self.details.author = "@author"
    self.details.version = "0.01"
    self.details.date = "15/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      return
    return


Manager().register_plugin(template)

