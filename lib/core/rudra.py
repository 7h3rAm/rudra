from aayudh.pcapanalysis import PCAPAnalysis
from aayudh.peanalysis import PEAnalysis
from aayudh.filemeta import FileMeta
from aayudh.protoid import ProtoID
from aayudh.scanner import Scanner
from aayudh import utils, fileutils

from lib import get_version_string, get_author
from lib.external import PluginManager
from lib.core.report import Report

from pprint import pprint
import code
import json
import time
import sys
import os


class Rudra:
  def __init__(self, session):
    self.session = utils.objdict(session)
    self.session.report = utils.objdict({})

    if not self.session.config.nobanner:
      self.session.banner = """
                    .___
  _______  __ __   __| _/_______ _____
  \_  __ \|  |  \ / __ | \_  __ \\\\__  \\
   |  | \/|  |  // /_/ |  |  | \/ / __ \_
   |__|   |____/ \____ |  |__|   (____  / v%s
                      \/              \/ (%s)
""" % (get_version_string(), get_author())
      print self.session.banner

    self.session.config.basereportsdir = "%s/%s" % (os.getcwd(), self.session.config.reportsdir)

    if self.session.config.interactive:
      self.interactive()

    elif self.session.config.inputfiles and len(self.session.config.inputfiles) > 0:
      if self.session.config.enableplugins:
        self.load_plugins()

      # analyze file and populate reports dict
      self.session.config.inputfiles.sort(key=str)
      for filename in self.session.config.inputfiles:
        filesha2 = fileutils.file_hashes(filename, "sha256")
        if filesha2 in self.session.config.blacklistsha256:
          utils.warn("%s is blacklisted! Skipping." % filename)
          continue

        # retain source-like report directory structure
        if self.session.config.reportsdirstruct:
          D1 = (-1 * self.session.config.reportsdirstructlevel) - 1
          D2 = self.session.config.reportsdirstructlevel
          self.session.config.currreportdir = "/".join(filename.split("/")[D1:][:D2])
          self.session.config.currreportfile = filename.split("/")[D1:][-1]
          self.session.config.currreportpath = "%s/%s/%s" % (self.session.config.basereportsdir, self.session.config.currreportdir, self.session.config.currreportfile.replace(".", "_"))
        else:
          self.session.config.currreportfile = filesha2
          self.session.config.currreportpath = "%s/%s" % (self.session.config.basereportsdir, filesha2)

        # check if file is already scanned, rescan only if requested
        if self.already_scanned(filesha2) and not self.session.config.rescan:
          utils.info("%s: %s" % (filename, "%s/%s.json" % (self.session.config.currreportpath, self.session.config.currreportfile)))
          self.session.report = fileutils.file_json_open("%s/%s.json" % (self.session.config.currreportpath, self.session.config.currreportfile))
          # convert the loaded json report into objdict for plugins to use
          self.report_to_objdict()
        else:
          self.analyze(filename)

        # run plugins over report objdict
        if self.session.config.enableplugins:
          self.run_plugins()

    else:
      utils.error("Please use -f to scan a file or -d to scan a directory of files or use -i for interactive mode")

  def str(self):
    return pprint.PrettyPrinter().pformat(self.session.report)

  def repr(self):
    return self.str()

  def already_scanned(self, filesha2):
    if fileutils.is_file("%s/%s.json" % (self.session.config.currreportpath, self.session.config.currreportfile)):
      return True
    return False

  # Inspired from following posts:
  # https://github.com/k4ml/importutils.error/blob/master/posts/python-custom-interactive-console.md
  # stackoverflow.com/questions/19754458/open-interactive-python-console-from-a-script
  def interactive(self):
    utils.set_prompt(ps1="(rudra) ", ps2="... ")

    import os
    import readline
    import rlcompleter
    import atexit

    histfile = os.path.join(os.environ["HOME"], ".rudrahistory")
    if os.path.isfile(histfile):
      readline.read_history_file(histfile)
    atexit.register(readline.write_history_file, histfile)

    r = self
    print "Use the \"r\" object to analyze files"

    vars = globals()
    vars.update(locals())
    readline.set_completer(rlcompleter.Completer(vars).complete)
    readline.parse_and_bind("tab: complete")

    del os, histfile, readline, rlcompleter, atexit
    code.interact(banner="", local=vars)

  def analyze(self, filename):
    if not fileutils.is_file(filename):
      utils.warn("%s is not a file." % filename)
      return

    timing = utils.objdict({})
    timing.starttime = time.time()
    self.session.config.reportsdir = "%s/%s/" % (self.session.config.basereportsdir, fileutils.file_hashes(filename, "sha256"))
    print "Starting analysis on %s @ %s" % (filename, utils.time_to_local_string(timing.starttime))

    ## refrain scanning a file more than once
    ## include db checks and ensure config similarity
    ## or check if the report file already exists in reports directory

    ## populate these after syncing with db
    self.session.report.misc = utils.objdict({})
    #self.session.report.misc.firstseen = utils.current_datetime_string()
    #self.session.report.misc.lastseen = utils.current_datetime_string()

    filesize = fileutils.file_size(filename)
    if self.session.config.statsfilesizelimit == 0 or filesize <= self.session.config.statsfilesizelimit:
      # limit is equal to 0 or filesize is lesser than limit
      # all good, keep going
      pass
    else:
      utils.info("Disabling entropy compression stats calculation and file visualization (filesize: %d, statsfilesizelimit: %d)" % (filesize, self.session.config.statsfilesizelimit))
      self.session.config.enableentropycompressionstats = False
      self.session.config.enablefilevisualization = False

    if not self.session.config.enablegeoloc:
      # if geodata lookup is disabled
      # map cannot be shown, so disable it explicitly
      self.session.config.enablegooglemaps = False
      utils.info("Geolocation is disabled in config and as such Google Maps layout is being auto-disabled")

    # initialize filemeta specific classes and call analysis methods
    utils.info("Invoking filemeta module for type identification and metadata collection")
    filemeta = FileMeta(filename=filename, config=self.session.config)
    if filemeta:
      filemeta.analyze()
      self.session.report.meta = filemeta.report
      if not self.session.config.enableentropycompressionstats:
        self.session.report.meta.filesize = filesize
    else:
      self.session.report.meta = None

    if filemeta and self.session.report.meta and self.session.report.meta.filemimetype == "application/vnd.tcpdump.pcap":
      if self.session.config.enablepcap:
        utils.info("Invoking pcapanalysis module for host identification, dns/http/ftp/smtp/pop3/imap probing and flow inspection")
        pcapid = PCAPAnalysis(filename=filename, config=self.session.config)
        if pcapid:
          pcapid.analyze()
          self.session.report.pcap = pcapid.report
        else:
          self.session.report.pcap = None
      else:
        self.session.report.pcap = None

    elif filemeta and self.session.report.meta and self.session.report.meta.filemimetype == "application/x-dosexec":
      if self.session.config.enablepe:
        utils.info("Invoking peanalysis module for scanning file and identifying threat indicators")
        pea = PEAnalysis(filename=filename, config=self.session.config)
        if pea:
          pea.analyze()
          self.session.report.pe = pea.report
        else:
          self.session.report.pe = None
      else:
        self.session.report.pe = None

    timing.endtime = time.time()
    timing.elapsedtime = timing.endtime - timing.starttime
    self.session.report.misc.config = self.session.config

    self.save()
    print "Completed analysis on %s @ %s (Elapsed: %s)" % (filename, utils.time_to_local_string(timing.endtime), utils.elapsed_time_string(timing.elapsedtime))

  # save session report to a json and/or html file
  def save(self):
    if self.session.config.savereport:
      if len(self.session.report.keys()) > 0:

        if self.session.config.enablefilevisualization:
          self.session.report.meta.visual.pnggray = utils.to_base64(self.session.report.meta.visual.pnggray)
          self.session.report.meta.visual.pngrgb = utils.to_base64(self.session.report.meta.visual.pngrgb)
          self.session.report.meta.visual.identicon = utils.to_base64(self.session.report.meta.visual.identicon) if self.session.report.meta.visual.identicon else None

        fileutils.file_save(filename="%s/%s.json" % (self.session.config.currreportpath, self.session.config.currreportfile), data=json.dumps(self.session.report, sort_keys=True, encoding="latin-1"))
        if self.session.config.verbose:
          utils.debug("Dumped reports to %s" % self.session.config.currreportpath)
      else:
        utils.warn("Nothing to save! Run analyze() and then save()")

  # https://github.com/hiddenillusion/example-code
  def load_plugins(self):
    main_plugin_directory = "lib/plugins"

    plugins = PluginManager.Manager().get_all_plugins(main_plugin_directory)
    for plugin_name, plugin_directory in plugins.iteritems():
      found_plugin = PluginManager.Manager().find_plugin(plugin_name, plugin_directory)
      if found_plugin:
        activated_plugin = PluginManager.Manager().load_plugin(plugin_name, found_plugin)

  def run_plugins(self):
    for plugin_name, plugin_class in PluginManager.PluginInterface().registry.iteritems():
      try:
        #PluginManager.Manager().show_plugin_details(plugin_class)
        PluginManager.Manager().run_plugin(plugin_class, self.session.report)
      except AttributeError as err:
        print err
        pass

  def report_to_objdict(self):
    self.session.report = utils.objdict(self.session.report)

    self.session.report.misc = utils.objdict(self.session.report.misc)
    self.session.report.misc.config = utils.objdict(self.session.report.misc.config)

    self.session.report.meta = utils.objdict(self.session.report.meta)
    self.session.report.meta.hashes = utils.objdict(self.session.report.meta.hashes)
    self.session.report.meta.visual = utils.objdict(self.session.report.meta.visual)

    if "pe" in self.session.report:
      self.session.report.pe = utils.objdict(self.session.report.pe)
      self.session.report.pe.static = utils.objdict(self.session.report.pe.static)
      if self.session.report.pe.static.authenticode:
        self.session.report.pe.static.authenticode = utils.objdict(self.session.report.pe.static.authenticode)
        if utils.objdict(self.session.report.pe.static.authenticode.hashes):
          self.session.report.pe.static.authenticode.hashes = utils.objdict(self.session.report.pe.static.authenticode.hashes)
        else:
          self.session.report.pe.static.authenticode.hashes = None
      else:
        self.session.report.pe.static.authenticode = None
      self.session.report.pe.static.dosheader = utils.objdict(self.session.report.pe.static.dosheader)
      self.session.report.pe.static.dosheader.dosstub = utils.objdict(self.session.report.pe.static.dosheader.dosstub) if "dosstub" in self.session.report.pe.static.dosheader and self.session.report.pe.static.dosheader.dosstub else None
      self.session.report.pe.static.hashes = utils.objdict(self.session.report.pe.static.hashes)
      self.session.report.pe.static.ntheaders = utils.objdict(self.session.report.pe.static.ntheaders)
      self.session.report.pe.static.ntheaders.fileheader = utils.objdict(self.session.report.pe.static.ntheaders.fileheader)
      self.session.report.pe.static.ntheaders.fileheader.Characteristics = utils.objdict(self.session.report.pe.static.ntheaders.fileheader.Characteristics)
      self.session.report.pe.static.ntheaders.optionalheader = utils.objdict(self.session.report.pe.static.ntheaders.optionalheader)
      self.session.report.pe.static.ntheaders.optionalheader.DllCharacteristics = utils.objdict(self.session.report.pe.static.ntheaders.optionalheader.DllCharacteristics)
      sections = list()
      if self.session.report.pe.static.ntheaders.sections:
        for section in self.session.report.pe.static.ntheaders.sections:
          secname = section.keys()[0]
          section[secname] = utils.objdict(section[secname])
          section[secname].Characteristics = utils.objdict(section[secname]["Characteristics"])
          section[secname].Characteristics.flags = utils.objdict(section[secname]["Characteristics"]["flags"])
          section[secname].checks = utils.objdict(section[secname]["checks"])
          section[secname].hashes = utils.objdict(section[secname]["hashes"])
          sections.append(utils.objdict(section))
        self.session.report.pe.static.ntheaders.sections = sections
      else:
        self.session.report.pe.static.ntheaders.sections = None
      if self.session.report.pe.static.overlay:
        self.session.report.pe.static.overlay = utils.objdict(self.session.report.pe.static.overlay)
        if utils.objdict(self.session.report.pe.static.overlay.hashes):
          self.session.report.pe.static.overlay.hashes = utils.objdict(self.session.report.pe.static.overlay.hashes)
        else:
          self.session.report.pe.static.overlay.hashes = None
      else:
        self.session.report.pe.static.overlay = None
      self.session.report.pe.static.strings = utils.objdict(self.session.report.pe.static.strings)
      self.session.report.pe.static.versioninfo = utils.objdict(self.session.report.pe.static.versioninfo)
      self.session.report.pe.static.versioninfo.fileinfo = utils.objdict(self.session.report.pe.static.versioninfo.fileinfo)
      self.session.report.pe.dynamic = utils.objdict(self.session.report.pe.dynamic)
      self.session.report.pe.dynamic.registry = utils.objdict(self.session.report.pe.dynamic.registry)
      self.session.report.pe.dynamic.filesystem = utils.objdict(self.session.report.pe.dynamic.filesystem)
      self.session.report.pe.scan = utils.objdict(self.session.report.pe.scan)
      self.session.report.pe.indicators = utils.objdict(self.session.report.pe.indicators)
      self.session.report.pe.indicators.checks = utils.objdict(self.session.report.pe.indicators.checks)
      self.session.report.pe.indicators.flags = utils.objdict(self.session.report.pe.indicators.flags)
    elif "pcap" in self.session.report:
      self.session.report.pcap = utils.objdict(self.session.report.pcap)
      self.session.report.pcap.indicators = utils.objdict(self.session.report.pcap.indicators)
      self.session.report.pcap.indicators.checks = utils.objdict(self.session.report.pcap.indicators.checks)
      self.session.report.pcap.indicators.flags = utils.objdict(self.session.report.pcap.indicators.flags)
      self.session.report.pcap.parsed = utils.objdict(self.session.report.pcap.parsed)

      flows = list()
      for flow in self.session.report.pcap.parsed.flows:
        flow = utils.objdict(flow)
        flow.scan = utils.objdict(flow.scan)
        flow.scan.shellcode = utils.objdict(flow.scan.shellcode)
        flow.scan.yara = utils.objdict(flow.scan.yara)

        flow.stats = utils.objdict(flow.stats)
        flow.stats.cts = None if "cts" not in flow.stats or not flow.stats.cts else utils.objdict(flow.stats.cts)
        flow.stats.stc = None if "stc" not in flow.stats or not flow.stats.stc else utils.objdict(flow.stats.stc)

        flows.append(utils.objdict(flow))
      self.session.report.pcap.flows = flows

      self.session.report.pcap.parsed.hosts = utils.objdict(self.session.report.pcap.parsed.hosts)
      self.session.report.pcap.parsed.counts = utils.objdict(self.session.report.pcap.parsed.counts)

