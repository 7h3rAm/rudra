#!/usr/bin/env python

__name__ = "Rudra"
__description__ = "The destroyer of evil"

__author__ = "@7h3rAm"
__mail__ = "7h3rAm - gmail"

__major__, __minor__, __patch__ = 0, 2, 0
__version__ = "%d.%d.%d" % (__major__, __minor__, __patch__)

def get_version_number():
  return (__major__, __minor__, __patch__)

def get_version_string():
  return __version__

def get_author():
  return __author__
