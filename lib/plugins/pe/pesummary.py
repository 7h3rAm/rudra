from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class pesummary(PluginInterface):
  name = "pesummary"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Display a summary of PE analysis"
    self.details.mimetypes = ["application/x-dosexec"]
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "15/OCT/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      borderflag = False
      headerflag = False
      padwidth = 1

      # show header and meta info
      tab = PrettyTable(["Atrribute", "Value"])
      tab.border = borderflag
      tab.header = headerflag
      tab.padding_width = padwidth
      tab.align["Atrribute"] = "l"
      tab.align["Value"] = "l"

      if report.pe.static.versioninfo:
        if report.pe.static.versioninfo.FileVersion:
          tab.add_row(["Version", report.pe.static.versioninfo.FileVersion])
        if report.pe.static.versioninfo.FileDescription:
          tab.add_row(["Description", report.pe.static.versioninfo.FileDescription])
        if report.pe.static.versioninfo.OriginalFilename:
          tab.add_row(["OriginalFilename", report.pe.static.versioninfo.OriginalFilename])
        if report.pe.static.versioninfo.CompanyName:
          tab.add_row(["CompanyName", report.pe.static.versioninfo.CompanyName])
        if report.pe.static.versioninfo.LegalCopyright:
          tab.add_row(["LegalCopyright", report.pe.static.versioninfo.LegalCopyright])
        if report.pe.static.versioninfo.Language_verbose:
          tab.add_row(["Language", report.pe.static.versioninfo.Language_verbose])

      if report.pe.static:
        tab.add_row(["Magic", report.pe.static.ntheaders.optionalheader.Magic_verbose])
        tab.add_row(["Machine", report.pe.static.ntheaders.fileheader.Machine_verbose])
        tab.add_row(["Subsystem", report.pe.static.ntheaders.optionalheader.Subsystem_verbose])
        tab.add_row(["Compiletime", report.pe.static.ntheaders.fileheader.TimeDateStamp_verbose])
        tab.add_row(["Entrypoint", "0x%x" % report.pe.static.ntheaders.optionalheader.AddressOfEntryPoint if report.pe.static.ntheaders.optionalheader.AddressOfEntryPoint else 0])
        tab.add_row(["ImageBase", "0x%x" % report.pe.static.ntheaders.optionalheader.ImageBase if report.pe.static.ntheaders.optionalheader.ImageBase else 0])
        tab.add_row(["Sections", "0x%x" % report.pe.static.ntheaders.fileheader.NumberOfSections if report.pe.static.ntheaders.fileheader.NumberOfSections else 0])
        tab.add_row(["Checksum", "0x%x" % report.pe.static.ntheaders.optionalheader.CheckSum if report.pe.static.ntheaders.optionalheader.CheckSum else 0])
        hashtab = PrettyTable(["Hash", "Value"])
        hashtab.border = False
        hashtab.header = False
        hashtab.padding_width = 1
        hashtab.align["Hash"] = "l"
        hashtab.align["Value"] = "l"
        hashtab.add_row(["Authentihash", report.pe.static.hashes.authentihash])
        hashtab.add_row(["Imphash", report.pe.static.hashes.imphash])
        hashtab.add_row(["PEhash", report.pe.static.hashes.pehash])
        tab.add_row(["Hashes", hashtab.get_string()])
        result = tab.get_string()
        if result != "":
          print "\nPE Information:\n%s" % result.encode("utf-8")

        # show PE authenticode details
        if report.pe.static.authenticode:
          tab = PrettyTable(["Atrribute", "Value"])
          tab.border = borderflag
          tab.header = headerflag
          tab.padding_width = padwidth
          tab.align["Atrribute"] = "l"
          tab.align["Value"] = "l"
          if report.pe.static.authenticode.certs:
            for certentry in report.pe.static.authenticode.certs:
              tab.add_row(["Issuer", certentry["issuer"]])
              tab.add_row(["Subject", certentry["subject"]])
              tab.add_row(["Validity", "%s - %s" % (certentry["notbefore"], certentry["notafter"])])
              tab.add_row(["", ""])
            result = tab.get_string()
            if result != "":
              print "\nAuthenticode:\n%s" % result

        # show PE section details
        if report.pe.static.ntheaders.sections:
          tab = PrettyTable(["Name", "VirtualAddress", "VirtualSize", "SizeOfRawData", "Entropy", "Permission", "Classification"])
          tab.border = borderflag
          tab.header = True
          tab.padding_width = padwidth
          tab.align["Name"] = "l"
          for entry in report.pe.static.ntheaders.sections:
            secname = entry.keys()[0]
            tab.add_row([secname, "0x%x" % entry[secname].VirtualAddress, "0x%x" % entry[secname].Misc_VirtualSize, \
              "0x%x" % entry[secname].SizeOfRawData, entry[secname].entropy, entry[secname].permissions, \
              "%s" % (entry[secname].classification)])
          result = tab.get_string()
          if result != "":
            print "\nSections:\n%s" % result

        # show PE data directories
        if report.pe.static.ntheaders.datadirectory:
          tab = PrettyTable(["Name", "Section", "Size", "VirtualAddress"])
          tab.border = borderflag
          tab.header = True
          tab.padding_width = padwidth
          tab.align["Name"] = "l"
          for datadir in report.pe.static.ntheaders.datadirectory:
            tab.add_row([datadir["Name"], datadir["Section"], "0x%x" % datadir["Size"], "0x%x" % datadir["VirtualAddress"]])
          result = tab.get_string()
          if result != "":
            print "\nData Directories:\n%s" % result

        # show stack/heap reserve/commit size
        tab = PrettyTable(["", "CommitSize", "ReserveSize"])
        tab.border = borderflag
        tab.header = True
        tab.padding_width = padwidth
        tab.align["CommitSize"] = "l"
        tab.align["ReserveSize"] = "l"
        tab.add_row(["Stack", "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfStackCommit if report.pe.static.ntheaders.optionalheader.SizeOfStackCommit else 0, "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfStackReserve if report.pe.static.ntheaders.optionalheader.SizeOfStackReserve else 0])
        tab.add_row(["Heap", "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfHeapCommit if report.pe.static.ntheaders.optionalheader.SizeOfHeapCommit else 0, "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfHeapReserve if report.pe.static.ntheaders.optionalheader.SizeOfHeapReserve else 0])
        result = tab.get_string()
        if result != "":
          print "\n%s" % result

      # show PE flags
      if report.pe.indicators.flags:
        tab = PrettyTable(["Flag", "Status"])
        tab.border = borderflag
        tab.header = headerflag
        tab.padding_width = padwidth
        tab.align["Flag"] = "l"
        tab.align["Status"] = "l"
        for flag in report.pe.indicators.flags.keys():
          tab.add_row([flag, report.pe.indicators.flags[flag]])
        result = tab.get_string(sortby="Status", reversesort=True)
        if result != "":
          print "\nFlags:\n%s" % result

      # show PE indicators
      if report.pe.indicators.checks:
        tab = PrettyTable(["Indicator", "Reason"])
        tab.border = borderflag
        tab.header = headerflag
        tab.padding_width = padwidth
        tab.align["Indicator"] = "l"
        tab.align["Reason"] = "l"
        for indicator in report.pe.indicators.checks.keys():
          if hasattr(report.pe.indicators.checks[indicator], "classification") and report.pe.indicators.checks[indicator].classification == "SUSPICIOUS":
            # indicator reason could include unicode chars (section names, etc.) and as such need sanitization before printing
            # http://stackoverflow.com/questions/2365411/python-convert-unicode-to-ascii-without-errors
            tab.add_row([indicator, "%s" % report.pe.indicators.checks[indicator].reason.decode("windows-1252").encode("ascii","ignore")])
        result = tab.get_string(sortby="Indicator", reversesort=False)
        if result != "":
          print "\nSuspicious Indicators:\n%s" % result

      # show PE warnings
      if report.pe.indicators.warnings:
        tab = PrettyTable(["Warnings"])
        tab.border = borderflag
        tab.header = headerflag
        tab.padding_width = padwidth
        tab.align["Warnings"] = "l"
        for warning in report.pe.indicators.warnings:
          tab.add_row([warning])
        result = tab.get_string(sortby="Warnings", reversesort=False)
        if result != "":
          print "\nWarnings:\n%s" % result

      # show PE scan results
      if report.pe.scan:
        tab = PrettyTable(["ScanType", "Result"])
        tab.border = borderflag
        tab.header = headerflag
        tab.padding_width = padwidth
        tab.align["ScanType"] = "l"
        tab.align["Result"] = "l"

        if report.pe.scan.adobemalwareclassifier:
          adobetab = PrettyTable(["Algorithm", "Classification"])
          adobetab.border = borderflag
          adobetab.header = headerflag
          adobetab.padding_width = padwidth
          adobetab.align["Algorithm"] = "l"
          for algorithm in report.pe.scan.adobemalwareclassifier:
            adobetab.add_row([algorithm, report.pe.scan.adobemalwareclassifier[algorithm]])
          result = adobetab.get_string()
          if result != "":
            tab.add_row(["Adobe Malware Classifier", result])
            tab.add_row(["", ""])

        if report.pe.scan.antivm:
          antivmtab = PrettyTable(["StartEnd", "Name"])
          antivmtab.border = borderflag
          antivmtab.header = headerflag
          antivmtab.padding_width = padwidth
          antivmtab.align["Name"] = "l"
          for entry in report.pe.scan.antivm:
            antivmtab.add_row(["[%d:%d]" % (entry["start"], entry["end"]), entry["name"]])
          result = antivmtab.get_string()
          if result != "":
            tab.add_row(["AntiVM", result])
            tab.add_row(["", ""])

        if report.pe.scan.mutex:
          mutextab = PrettyTable(["Mutex", "Threat"])
          mutextab.border = borderflag
          mutextab.header = headerflag
          mutextab.padding_width = padwidth
          mutextab.align["Mutex"] = "l"
          for entry in report.pe.scan.mutex:
            mutextab.add_row([entry["value"], entry["threat"]])
          result = mutextab.get_string()
          if result != "":
            tab.add_row(["Mutexes", result])
            tab.add_row(["", ""])

        if report.pe.scan.regex:
          regextab = PrettyTable(["StartEnd", "Description"])
          regextab.border = borderflag
          regextab.header = headerflag
          regextab.padding_width = padwidth
          regextab.align["Name"] = "l"
          for entry in report.pe.scan.regex:
            regextab.add_row(["[%d:%d]" % (entry["start"], entry["end"]), entry["description"]])
          result = regextab.get_string()
          if result != "":
            tab.add_row(["Regex", result])
            tab.add_row(["", ""])

        if report.pe.scan.shellcode:
          tab.add_row(["Shellcode", "0x%x" % report.pe.scan.shellcode.offset])
          tab.add_row(["", ""])

        if report.pe.scan.online and report.pe.scan.online["virustotal"]:
          virustotaltab = PrettyTable(["Result", "ScanDate"])
          virustotaltab.border = borderflag
          virustotaltab.header = headerflag
          virustotaltab.padding_width = padwidth
          virustotaltab.align["Result"] = "l"
          virustotaltab.align["ScanDate"] = "l"
          virustotaltab.add_row(["%s" % report.pe.scan.online["virustotal"]["filereport"]["scan_date"], "%d/%d" % (report.pe.scan.online["virustotal"]["filereport"]["positives"], report.pe.scan.online["virustotal"]["filereport"]["total"])])
          result = virustotaltab.get_string()
          if result != "":
            tab.add_row(["VirusTotal", result])
            tab.add_row(["", ""])

        if report.pe.scan.whitelist:
          whitelisttab = PrettyTable(["Source", "Whitelisted"])
          whitelisttab.border = borderflag
          whitelisttab.header = headerflag
          whitelisttab.padding_width = padwidth
          whitelisttab.align["Source"] = "l"
          whitelisttab.add_row(["NSRL", report.pe.scan.whitelist["nsrl"]])
          whitelisttab.add_row(["Mandiant", report.pe.scan.whitelist["mandiant"]])
          result = whitelisttab.get_string(sortby="Whitelisted", reversesort=True)
          if result != "":
            tab.add_row(["Whitelist", result])
            tab.add_row(["", ""])

        if report.pe.scan.yara:
          yaratab = PrettyTable(["Rules"])
          yaratab.border = borderflag
          yaratab.header = headerflag
          yaratab.padding_width = padwidth
          yaratab.align["Rules"] = "l"
          for rulename in report.pe.scan.yara.keys():
            yaratab.add_row([rulename])
          result = yaratab.get_string(sortby="Rules", reversesort=False)
          if result != "":
            tab.add_row(["Yara", result])

      result = tab.get_string()
      if result != "":
        print "\nScan Results:\n%s" % result


Manager().register_plugin(pesummary)

