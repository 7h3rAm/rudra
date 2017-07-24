#!/usr/bin/env python

# created by Glenn P. Edwards Jr.
#   http://hiddenillusion.blogspot.com
#       @hiddenillusion
# Date: 2015-04-10
# (while at FireEye)

import os
import sys
import imp
import traceback
from pprint import pprint


class Manager(object):
  def __init__(self, plugin_directory=None, plugin=None):
    self._plugin_directory = plugin_directory
    self._plugin = plugin
    self._plugin_classes = {}

  def get_all_plugins(self, plugin_directory):
    plugins = {}
    for plugin in RecursePath(plugin_directory):
      plugin_name = os.path.basename(plugin)
      plugin_path = os.path.dirname(plugin)
      if plugin_name.endswith(".py") and plugin_name[:-3] != "__init__":
        plugin_name = plugin_name[:-3]
        plugins[plugin_name] = plugin_path

    return plugins

  def list_plugin(self, plugin_directory):
    for plugin in self.get_all_plugins(plugin_directory):
      print plugin

  def find_plugin(self, plugin, plugin_directory):
    try:
      found_plugins = imp.find_module(plugin, [plugin_directory])
    except ImportError as err:
      print "[!] {0}".format(err)
      return

    return found_plugins

  def load_plugin(self, plugin, found_plugin):
    try:
      module = imp.load_module(plugin, found_plugin[0], found_plugin[1], found_plugin[2])
    except ImportError as err:
      print "[i] ImportError for '{0}'".format(found_plugin[0], err)
      print traceback.print_exc()
      return
    except TypeError as err:
      print "[i] TypeError for '{0}'".format(found_plugin[0], err)
      print traceback.format_exc()
      return
    except Exception as err:
      print "[i] Misc. Error for '{0}'".format(found_plugin[0], err)
      print traceback.format_exc()
      return

    return module

  def register_plugin(cls, plugin_class):
    parser_name = plugin_class.name.lower()
    if parser_name in cls._plugin_classes:
      raise KeyError(('Parser class already set for name: {0:s}.').format(plugin_class.name))

    cls._plugin_classes[parser_name] = plugin_class

  def show_plugin_details(self, cls_name):
    try:
      cls_obj = cls_name()
      if hasattr(cls_obj, "details"):
        pprint(cls_obj.details)
    except Exception as ex:
      print traceback.format_exc()
      pass

  def run_plugin(self, cls_name, arg):
    try:
      if hasattr(cls_name, "enabled") and cls_name.enabled:
        if hasattr(cls_name, "run"):
          cls_name().run(arg)
    except Exception as ex:
      print traceback.format_exc()
      pass


class PluginInterfaceMeta(type):
  def __init__(cls, name, bases, dct):
    super(PluginInterfaceMeta, cls).__init__(name, bases, dct)
    if not hasattr(cls, 'registry'):
      cls.registry = {}
    cls.registry[name.lower()] = cls


class PluginInterface(object):
  __metaclass__ = PluginInterfaceMeta


def RecursePath(path):
  """
  Didn't realize os.walk() returns a list in arbitrary order
  so the default is going to be a sorted list on each level
  of recursion.

  @path : A path to recurse and look for files
  @return : A generator containing full file paths to any file
        found while recursing @path
  """
  if not os.path.exists(path):
    # First check will be to see if @path ended with a slash and was quoted.
    # This helps with spaces in the path but will treat the last " as a
    #  literal character and leave it at the end of the path, making it
    #  non-existing.
    path = path.rstrip('"')
    if not os.path.exists(path):
      return

  if os.path.exists(path):
    if os.path.isdir(path):
      for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
          fname = os.path.join(root, name)
          if os.path.isfile(fname):
            yield fname
          else:
            pass
    else:
      if os.path.isfile(path):
        yield path

