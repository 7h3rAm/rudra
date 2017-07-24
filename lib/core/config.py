from aayudh import utils, fileutils

import ConfigParser
import sys
import os


class Config:
  def __init__(self, configfile=None):
    # max bytes (within respective protocol buffers) to inspect
    self.MAX_INSPECT_UDP_DEPTH = 8192
    self.MAX_INSPECT_CTS_DEPTH = 8192
    self.MAX_INSPECT_STC_DEPTH = 8192

    self.conf = utils.objdict({})

    self.configfile = os.path.abspath(configfile)
    self.config = ConfigParser.SafeConfigParser()

    if configfile and fileutils.is_file(configfile):
      self.config.read(self.configfile)

  def read_as_dict(self):
    for section in self.config.sections():
      for option in self.config.options(section):

        # lists in the config options
        if option in ["inputfiles"]:
          self.conf[option] = []
          for infile in self.config.get(section, option).strip().split(","):
            self.conf[option].append(infile.strip())

        elif option in ["supportedmimetypes", "blacklistsha256"]:
          self.conf[option] = []
          for reporttype in self.config.get(section, option).strip().lower().split(","):
            self.conf[option].append(reporttype.strip())

        # booleans in config options
        elif option in [
            "enablewhoislookup", "enablefilevisualization", "enablegooglemaps",
            "enablebytefreqhistogramtransactions", "enablefilevisualizationtransactions",
            "enablebufhexdump", "enablepcap", "enableyara", "nobanner", "enableshellcode",
            "shellcodeshowhexdump", "enableregex", "enableheuristics", "interactive", "extractsubfiles",
            "enablegeoloc", "enableyarastrings", "enableentropycompressionstats", "extractstringsunicode"
            "enablestatsfilesizelimit", "enablereversedns", "enableprotodecode", "verbose", "savereport",
            "enableplugins", "enableonlinelookup", "reportsdirstruct", "rescan"
          ]:
          if self.config.get(section, option).lower() == "false":
            self.conf[option] = False

          if self.config.get(section, option).lower() == "true":
            self.conf[option] = True

        # ints in config options
        elif option in [
            "yaramatchtimeout", "htmlhexdumpbytes", "statsfilesizelimit", "reportsdirstructlevel",
            "inspectudpdepth", "inspectctsdepth", "inspectstcdepth", "truncatelength"
          ]:
          self.conf[option] = int(self.config.get(section, option))

        # everything else
        else:
          self.conf[option] = self.config.get(section, option)

    if "inspectudpdepth" in self.conf.keys() and (self.conf["inspectudpdepth"] > self.MAX_INSPECT_UDP_DEPTH or self.conf["inspectudpdepth"] <= 0):
      self.logger.debug("Imposing max UDP inspection depth: %d (config.inspectudpdepth: %d)" % (self.MAX_INSPECT_UDP_DEPTH, self.conf["inspectudpdepth"]))
      self.conf["inspectudpdepth"] = self.MAX_INSPECT_UDP_DEPTH

    if "inspectctsdepth" in self.conf.keys() and (self.conf["inspectctsdepth"] > self.MAX_INSPECT_CTS_DEPTH or self.conf["inspectctsdepth"] <= 0):
      self.logger.debug("Imposing max CTS inspection depth: %d (config.inspectctsdepth: %d)" % (self.MAX_INSPECT_CTS_DEPTH, self.conf["inspectctsdepth"]))
      self.conf["inspectctsdepth"] = self.MAX_INSPECT_CTS_DEPTH

    if "inspectstcdepth" in self.conf.keys() and (self.conf["inspectstcdepth"] > self.MAX_INSPECT_STC_DEPTH or self.conf["inspectstcdepth"] <= 0):
      self.logger.debug("Imposing max STC inspection depth: %d (config.inspectstcdepth: %d)" % (self.MAX_INSPECT_STC_DEPTH, self.conf["inspectstcdepth"]))
      self.conf["inspectstcdepth"] = self.MAX_INSPECT_STC_DEPTH

    return self.conf

  def set_defaults(self):
    self.config.add_section("MISC")
    self.set_var("MISC", "cwd", "./")
    self.set_var("MISC", "enableinteractive", "false")
    self.set_var("MISC", "htmlhexdumpbytes", "128")

    self.config.add_section("LOGGING")
    self.set_var("LOGGING", "loggingdir", "./")
    self.set_var("LOGGING", "loggingfile", "rudra.log")
    self.set_var("LOGGING", "logginglevel", "DEBUG")

    self.config.add_section("INPUT")
    self.set_var("INPUT", "inputfiles", "/home/shiv/toolbox/testfiles/pcaps/shellcode/shellcode-reverse-tcp-4444.pcap,")
    self.set_var("INPUT", "bpf", "ip")
    self.set_var("INPUT", "htmltemplate", "report.tmpl")

    self.config.add_section("OUTPUT")
    self.set_var("OUTPUT", "reportsdir", "./reports")
    self.set_var("OUTPUT", "reportstype", "json, html, pdf")
    self.set_var("OUTPUT", "enablebytefreq_histogram", "true")
    self.set_var("OUTPUT", "enablegoogle_maps", "true")
    self.set_var("OUTPUT", "enablewhoislookup", "true")

    self.config.add_section("ANALYSIS")
    self.set_var("ANALYSIS", "enablepcap", "true")
    self.set_var("ANALYSIS", "pcapengine", "libnids")
    self.set_var("ANALYSIS", "enableyara", "true")
    self.set_var("ANALYSIS", "yararules_dir", "./data/yararules")
    self.set_var("ANALYSIS", "yaramatchtimeout", "60")
    self.set_var("ANALYSIS", "enableshellcode", "true")

  def get_var(self, section, var):
    try:
      return self.config.get(section, var)
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
      return None

  def get_section(self, section):
    try:
      options = self.config.items(section)
    except ConfigParser.NoSectionError:
      return None

    opt_dict = dict()
    for pairs in options:
      opt_dict[pairs[0]] = pairs[1]

    return opt_dict

  def set_var(self, section, var, value):
    try:
      return self.config.set(section, var, value)
    except ConfigParser.NoSectionError:
      return None

  def list_config(self):
    print "Configuration Options:"
    for section in self.config.sections():
      print "%s" % (section)
      for (name, value) in self.config.items(section):
        print "\t%s:\t%s" % (name, value)
    return

