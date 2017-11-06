from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os
import re


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class pehtml(PluginInterface):
  name = "pehtml"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Dump the summary of PE analysis as HTML"
    self.details.mimetypes = ["application/x-dosexec"]
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "04/NOV/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      htmldata = ""
      htmlstarts = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <link href="http://fonts.googleapis.com/css?family=Roboto:300,400,400italic,500,700" rel="stylesheet" type="text/css" />

    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css" integrity="sha512-dTfge/zgoMYpP7QbHy4gWMEGsbsdZeCXz7irItjcC3sPUFtf0kuFbDz/ixG7ArTxmDjLXDmezHubeNikyKGVyQ==" crossorigin="anonymous">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap-theme.min.css" integrity="sha384-aUGj/X2zp5rLCbBxumKTCw2Z50WgIr1vs/PFN4praOTvYXWlVyh2UtNUU0KAUhAX" crossorigin="anonymous">
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js" integrity="sha512-K1qjQ+NcF2TYO/eI3M6v8EiNYZfA95pQumfvcVrTHtwQVDG+aHRqLi/ETn2uB+1JqwYqVG3LIvdm9lj6imS/pQ==" crossorigin="anonymous"></script>

    <!-- Include jQuery (Syntax Highlighter Requirement) -->
    <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script>
    <!-- Include jQuery Syntax Highlighter -->
    <script type="text/javascript" src="http://balupton.github.com/jquery-syntaxhighlighter/scripts/jquery.syntaxhighlighter.min.js"></script>
    <!-- Initialise jQuery Syntax Highlighter -->
    <script type="text/javascript">$.SyntaxHighlighter.init();</script>
    <!-- Initialise jQuery Syntax Highlighter -->
    <script type="text/javascript">
      $.SyntaxHighlighter.init({
        'wrapLines':true,
        'lineNumbers':false,
        'theme':'doxy'
      });
    </script>

    <style>
      body {
        font-family: "Roboto", "Helvetica Neue", Helvetica, Arial;
        background: url("/media/img/sandstone/bg-gradient-sand.26ec6264163e.png") repeat-x scroll 0% 0%, url("/media/img/sandstone/bg-sand.5f2ca98ac180.png") repeat scroll 0% 0%, #2D2D2D none repeat scroll 0% 0%;}div#hmenu {margin: 0;padding: .3em 0 .3em 0;width: 100%;text-align: center;}div#hmenu ul {list-style: none;margin: 0;padding: 0;}div#hmenu ul li {margin: 0;padding: 0;display: inline;}div#hmenu ul a:link {margin: 0;padding: .3em .4em .3em .4em;text-decoration: none;font-weight: bold;font-size: medium;}div#hmenu ul a:visited {margin: 0;padding: .3em .4em .3em .4em;text-decoration: none;font-weight: bold;font-size: medium;}div#hmenu ul a:active {margin: 0;padding: .3em .4em .3em .4em;text-decoration: none;font-weight: bold;font-size: medium;}div#hmenu ul a:hover {margin: 0;padding: .3em .4em .3em .4em;text-decoration: none;font-weight: bold;font-size: medium;}a {outline: 0;}.values {padding: 2px 4px;text-decoration: none;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}.sectionheader {background-color: #F8F8F8;border-color: #E7E7E7;border-style: dashed;border-width: 1px;border-radius: 3px;padding: 5px;}.highlight_cts {color: #A94442;padding: 2px 4px;text-decoration: none;font-size: 90%;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}.highlight_stc {color: #337AB7;padding: 2px 4px;text-decoration: none;font-size: 90%;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}.highlight_def {padding: 2px 4px;text-decoration: none;font-size: 110%;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}.scroll_cts {overflow: auto;white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;max-height: 200px;color: #A94442;padding: 2px 4px;text-decoration: none;font-size: 90%;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}.scroll_stc {overflow: auto;white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;max-height: 200px;color: #337AB7;padding: 2px 4px;text-decoration: none;font-size: 90%;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}.scroll_def {overflow: auto;white-space: pre-wrap; white-space: -moz-pre-wrap; white-space: -pre-wrap; white-space: -o-pre-wrap; word-wrap: break-word;max-height: 200px;padding: 2px 4px;text-decoration: none;font-size: 90%;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}th {background-color:#f5f5f5;}td {text-decoration: none;font-weight: bold;font-family: Menlo, Monaco, Consolas, "Courier New", monospace;}
      }
    </style>
    <title>{{TITLE}}</title>
  </head>
  <body>
    <br/>
    <div class="container-fluid">""".replace("{{TITLE}}", report.meta.hashes["sha256"])

      htmlends = """    </div>

  <footer class="footer">
    <div class="container"><center><b>
      <p class="text-muted">
        Generated on %s via Rudra v%s.<br/>This work is under <a href="http://creativecommons.org/licenses/by-nc-sa/4.0/" target="_blank">CC BY-NC-SA</a>. To report issues, reach out: <a href="mailto://7h3rAm@gmail.com">7h3rAm</a>
      </p>
    </b></center></div>
  </footer>

  </body>
</html>""" % (utils.current_datetime_string(), report.misc.config.version)

      htmldata = "%s\n" % (htmlstarts)

      if report.meta:
        borderflag = False
        headerflag = False
        padwidth = 1
        # show file metainfo
        metasummarytab = PrettyTable(["Attribute", "Value"])
        metasummarytab.border = borderflag
        metasummarytab.header = headerflag
        metasummarytab.padding_width = padwidth
        metasummarytab.align["Attribute"] = "l"
        metasummarytab.align["Value"] = "l"
        metasummarytab.add_row(["File", report.meta.filebasename])
        metasummarytab.add_row(["Location", report.meta.filedirname])
        metasummarytab.add_row(["MIMEType", report.meta.filemimetype])
        metasummarytab.add_row(["Magic", report.meta.filemagic])
        metasummarytab.add_row(["Size", report.meta.filesize])
        metasummarytab.add_row(["Minsize", "%s (%s%%)" % (report.meta.fileminsize, report.meta.filecompressionratio)])
        if report.meta.fileentropycategory in ["SUSPICIOUS", "PACKED"]:
          metasummarytab.add_row(["Entropy", "%s <span class='label label-warning'>%s</span>" % (report.meta.fileentropy, report.meta.fileentropycategory)])
        else:
          metasummarytab.add_row(["Entropy", "%s <span class='label label-info'>%s</span>" % (report.meta.fileentropy, report.meta.fileentropycategory)])

        robotab = """

<div class="col-md-2">
  <table class="table table-condensed table-hover table-striped">
    <tr rowspan="7" >
      <td><center><a href="%s.identicon"><img src="%s.identicon" height="200" width="200" title="identicon for %s"></a></center></td>
    </tr>
  </table>
</div>

""" % (report.misc.config.currreportfile, report.misc.config.currreportfile, report.misc.config.currreportfile)

        normalizeddata = metasummarytab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Meta Information</strong></div>\n<div class='panel-body'>\n<div class='row'>\n%s<div class='col-md-10'>\n<table class='table table-condensed table-hover table-striped'>" % robotab)
        htmldata += "%s\n" % (normalizeddata)

        visual = """
<div class="panel panel-info">
<div class="panel-heading"><strong>Visual</strong></div>
<div class="panel-body">
<div class="row">
<table class="table">
  <tr>
    <div class="col-md-3">
      <td><center><a href="%s.pnggray"><img src="%s.pnggray" height="522" width="256" title="Byte representation in grayscale"></a></center></td>
    </div>
    <div class="col-md-3">
      <td><center><a href="%s.pngrgb"><img src="%s.pngrgb" height="522" width="256" title="Byte representation in RGB"></a></center></td>
    </div>
    <div class="col-md-6">
      <td><center><a href="%s.bfh" title="Byte frequency histogram">%s</a></center></td>
    </div>
  </tr>
</table>
</div></div></div>\n"""

        htmldata += "%s\n" % (visual % (report.misc.config.currreportfile, report.misc.config.currreportfile, report.misc.config.currreportfile, report.misc.config.currreportfile, report.misc.config.currreportfile, report.meta.visual.bytefreqhistogram))

      # show hashes
      hashtab = PrettyTable(["Hash", "Value"])
      hashtab.border = borderflag
      hashtab.header = headerflag
      hashtab.padding_width = 1
      hashtab.align["Hash"] = "l"
      hashtab.align["Value"] = "l"
      hashtab.add_row(["CRC32", report.meta.hashes["crc32"]])
      hashtab.add_row(["MD5", report.meta.hashes["md5"]])
      hashtab.add_row(["SHA128", report.meta.hashes["sha1"]])
      hashtab.add_row(["SHA256", report.meta.hashes["sha256"]])
      hashtab.add_row(["SSDEEP", report.meta.hashes["ssdeep"]])
      hashtab.add_row(["Imphash", report.pe.static.hashes.imphash])
      hashtab.add_row(["PEhash", report.pe.static.hashes.pehash])
      normalizeddata = hashtab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Hashes</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
      htmldata += "%s\n" % (normalizeddata)

      # show header and meta info
      pemetatab = PrettyTable(["Atrribute", "Value"])
      pemetatab.border = borderflag
      pemetatab.header = headerflag
      pemetatab.padding_width = padwidth
      pemetatab.align["Atrribute"] = "l"
      pemetatab.align["Value"] = "l"
      if report.pe.static.versioninfo:
        if report.pe.static.versioninfo.FileVersion:
          pemetatab.add_row(["Version", report.pe.static.versioninfo.FileVersion])
        if report.pe.static.versioninfo.FileDescription:
          pemetatab.add_row(["Description", report.pe.static.versioninfo.FileDescription])
        if report.pe.static.versioninfo.OriginalFilename:
          pemetatab.add_row(["OriginalFilename", report.pe.static.versioninfo.OriginalFilename])
        if report.pe.static.versioninfo.CompanyName:
          pemetatab.add_row(["CompanyName", report.pe.static.versioninfo.CompanyName])
        if report.pe.static.versioninfo.LegalCopyright:
          pemetatab.add_row(["LegalCopyright", report.pe.static.versioninfo.LegalCopyright])
        if report.pe.static.versioninfo.Language_verbose:
          pemetatab.add_row(["Language", report.pe.static.versioninfo.Language_verbose])
      if report.pe.static:
        pemetatab.add_row(["Magic", report.pe.static.ntheaders.optionalheader.Magic_verbose])
        pemetatab.add_row(["Machine", report.pe.static.ntheaders.fileheader.Machine_verbose])
        pemetatab.add_row(["Subsystem", report.pe.static.ntheaders.optionalheader.Subsystem_verbose])
        pemetatab.add_row(["Compiletime", report.pe.static.ntheaders.fileheader.TimeDateStamp_verbose])
        pemetatab.add_row(["Entrypoint", "0x%x" % report.pe.static.ntheaders.optionalheader.AddressOfEntryPoint if report.pe.static.ntheaders.optionalheader.AddressOfEntryPoint else 0])
        pemetatab.add_row(["ImageBase", "0x%x" % report.pe.static.ntheaders.optionalheader.ImageBase if report.pe.static.ntheaders.optionalheader.ImageBase else 0])
        pemetatab.add_row(["Sections", "0x%x" % report.pe.static.ntheaders.fileheader.NumberOfSections if report.pe.static.ntheaders.fileheader.NumberOfSections else 0])
        pemetatab.add_row(["Checksum", "0x%x" % report.pe.static.ntheaders.optionalheader.CheckSum if report.pe.static.ntheaders.optionalheader.CheckSum else 0])
      normalizeddata = pemetatab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>PE Information</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
      htmldata += "%s\n" % (normalizeddata)

      # show PE indicators
      if report.pe.indicators.checks:
        indicatorstab = PrettyTable(["Indicator", "Classification", "Reason"])
        indicatorstab.border = borderflag
        indicatorstab.header = headerflag
        indicatorstab.header = True
        indicatorstab.padding_width = padwidth
        indicatorstab.align["Indicator"] = "l"
        indicatorstab.align["Classification"] = "l"
        indicatorstab.align["Reason"] = "l"
        for indicator in report.pe.indicators.checks.keys():
          if "classification" in report.pe.indicators.checks[indicator] and report.pe.indicators.checks[indicator]["classification"] in ["SUSPICIOUS"]:
            # indicator reason could include unicode chars (section names, etc.) and as such need sanitization before printing
            # http://stackoverflow.com/questions/2365411/python-convert-unicode-to-ascii-without-errors
            indicatorstab.add_row([indicator, "<span class='label label-warning'>%s</span>" % (report.pe.indicators.checks[indicator]["classification"].decode("windows-1252").encode("ascii","ignore")), "%s" % report.pe.indicators.checks[indicator]["reason"].decode("windows-1252").encode("ascii","ignore")])
          else:
            indicatorstab.add_row([indicator, "<span class='label label-info'>%s</span>" % (report.pe.indicators.checks[indicator]["classification"].decode("windows-1252").encode("ascii","ignore")), "%s" % report.pe.indicators.checks[indicator]["reason"].decode("windows-1252").encode("ascii","ignore")])
        normalizeddata = indicatorstab.get_html_string(sortby="Indicator", reversesort=False).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Indicators</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      # show PE warnings
      if report.pe.indicators.warnings:
        warningstab = PrettyTable(["Warnings"])
        warningstab.border = borderflag
        warningstab.header = headerflag
        warningstab.padding_width = padwidth
        warningstab.align["Warnings"] = "l"
        for warning in report.pe.indicators.warnings:
          warningstab.add_row([warning])
        normalizeddata = warningstab.get_html_string(sortby="Warnings", reversesort=False).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Warnings</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      # show PE flags
      if report.pe.indicators.flags:
        flagtab = PrettyTable(["Flag", "Status"])
        flagtab.border = borderflag
        flagtab.header = headerflag
        flagtab.padding_width = padwidth
        flagtab.align["Flag"] = "l"
        flagtab.align["Status"] = "l"
        onflags, offflags = list(), list()
        for flag in report.pe.indicators.flags.keys():
          if report.pe.indicators.flags[flag]:
            onflags.append(flag)
          else:
            offflags.append(flag)
        flagtab.add_row(["ON", ", ".join(sorted(onflags))])
        flagtab.add_row(["OFF", ", ".join(sorted(offflags))])

        normalizeddata = flagtab.get_html_string(sortby="Status", reversesort=True).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Flags</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      # show PE authenticode details
      if report.pe.static.authenticode and report.pe.static.authenticode.size:
        authenticodetab = PrettyTable(["Atrribute", "Value"])
        authenticodetab.border = borderflag
        authenticodetab.header = headerflag
        authenticodetab.padding_width = padwidth
        authenticodetab.align["Atrribute"] = "l"
        authenticodetab.align["Value"] = "l"
        if hasattr(report.pe.static.authenticode, "certs") and report.pe.static.authenticode.certs:
          for certentry in report.pe.static.authenticode.certs:
            authenticodetab.add_row(["Issuer", certentry["issuer"]])
            authenticodetab.add_row(["Subject", certentry["subject"]])
            authenticodetab.add_row(["Validity", "%s - %s" % (certentry["notbefore"], certentry["notafter"])])
            authenticodetab.add_row(["", ""])
        normalizeddata = authenticodetab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Authenticode</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      # show PE section details
      if report.pe.static.ntheaders.sections:
        sectiontab = PrettyTable(["Name", "VirtualAddress", "VirtualSize", "SizeOfRawData", "Entropy", "Permission", "Classification", "Reason"])
        sectiontab.border = borderflag
        sectiontab.header = True
        sectiontab.padding_width = padwidth
        sectiontab.align["Name"] = "l"
        for entry in report.pe.static.ntheaders.sections:
          secname = entry.keys()[0]
          reasons = "\n".join(entry[secname].classificationreasons) if entry[secname].classificationreasons else ""
          sectiontab.add_row([secname, "0x%x" % entry[secname].VirtualAddress, "0x%x" % entry[secname].Misc_VirtualSize, \
            "0x%x" % entry[secname].SizeOfRawData, entry[secname].entropy, entry[secname].permissions, \
            "<span class='label label-info'>%s</span>" % (entry[secname].classification) if entry[secname].classification == "CLEAN" else "<span class='label label-warning'>%s</span>" % (entry[secname].classification),
            reasons])
        normalizeddata = sectiontab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Sections</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      # show PE data directories
      if report.pe.static.ntheaders.datadirectory:
        datadirtab = PrettyTable(["Name", "Section", "Size", "VirtualAddress"])
        datadirtab.border = borderflag
        datadirtab.header = True
        datadirtab.padding_width = padwidth
        datadirtab.align["Name"] = "l"
        for datadir in report.pe.static.ntheaders.datadirectory:
          datadirtab.add_row([datadir["Name"], datadir["Section"], "0x%x" % datadir["Size"], "0x%x" % datadir["VirtualAddress"]])
        normalizeddata = datadirtab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Data Directories</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

        # show stack/heap reserve/commit size
        memsizetab = PrettyTable(["Area", "CommitSize", "ReserveSize"])
        memsizetab.border = borderflag
        memsizetab.header = True
        memsizetab.padding_width = padwidth
        memsizetab.align["CommitSize"] = "l"
        memsizetab.align["ReserveSize"] = "l"
        memsizetab.add_row(["Stack", "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfStackCommit if report.pe.static.ntheaders.optionalheader.SizeOfStackCommit else 0, "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfStackReserve if report.pe.static.ntheaders.optionalheader.SizeOfStackReserve else 0])
        memsizetab.add_row(["Heap", "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfHeapCommit if report.pe.static.ntheaders.optionalheader.SizeOfHeapCommit else 0, "0x%x" % report.pe.static.ntheaders.optionalheader.SizeOfHeapReserve if report.pe.static.ntheaders.optionalheader.SizeOfHeapReserve else 0])
        normalizeddata = memsizetab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Memory Allocations</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.adobemalwareclassifier:
        adobetab = PrettyTable(["Algorithm", "Classification"])
        adobetab.border = borderflag
        adobetab.header = True
        adobetab.padding_width = padwidth
        adobetab.align["Algorithm"] = "l"
        for algorithm in report.pe.scan.adobemalwareclassifier:
          if report.pe.scan.adobemalwareclassifier[algorithm] == "CLEAN":
            adobetab.add_row([algorithm, "<span class='label label-info'>%s</span>" % report.pe.scan.adobemalwareclassifier[algorithm]])
          else:
            adobetab.add_row([algorithm, "<span class='label label-warning'>%s</span>" % report.pe.scan.adobemalwareclassifier[algorithm]])
        normalizeddata = adobetab.get_html_string(sortby="Algorithm", reversesort=False).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Adobe Malware Classifier</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.antivm:
        antivmtab = PrettyTable(["StartEnd", "Name"])
        antivmtab.border = borderflag
        antivmtab.header = headerflag
        antivmtab.padding_width = padwidth
        antivmtab.align["Name"] = "l"
        for entry in report.pe.scan.antivm:
          antivmtab.add_row(["[%d:%d]" % (entry["start"], entry["end"]), entry["name"]])
        normalizeddata = antivmtab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>AntiVM</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.mutex:
        mutextab = PrettyTable(["Mutex", "Threat"])
        mutextab.border = borderflag
        mutextab.header = True
        mutextab.padding_width = padwidth
        mutextab.align["Mutex"] = "l"
        for entry in report.pe.scan.mutex:
          mutextab.add_row([entry["value"], entry["threat"]])
        normalizeddata = mutextab.get_html_string(sortby="Mutex", reversesort=False).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Mutexes</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.regex:
        regextab = PrettyTable(["StartEnd", "Description"])
        regextab.border = borderflag
        regextab.header = True
        regextab.padding_width = padwidth
        regextab.align["Name"] = "l"
        for entry in report.pe.scan.regex:
          regextab.add_row(["[%d:%d]" % (entry["start"], entry["end"]), entry["description"]])
        result = regextab.get_string()
        normalizeddata = regextab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Regexes</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.shellcode:
        shellcodetab = PrettyTable(["Attribute", "Value"])
        shellcodetab.border = borderflag
        shellcodetab.header = headerflag
        shellcodetab.padding_width = padwidth
        shellcodetab.align["Attribute"] = "l"
        shellcodetab.align["Value"] = "l"
        scantab.add_row(["Offset", "0x%x" % report.pe.scan.shellcode.offset])
        scantab.add_row(["Profile", report.pe.scan.shellcode.profile])
        normalizeddata = shellcodetab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Shellcode</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.online and report.pe.scan.online["virustotal"]:
        virustotaltab = PrettyTable(["ScanDate", "Score"])
        virustotaltab.border = borderflag
        virustotaltab.header = headerflag
        virustotaltab.padding_width = padwidth
        virustotaltab.align["ScanDate"] = "l"
        virustotaltab.align["Score"] = "l"
        virustotaltab.add_row(["%s" % report.pe.scan.online["virustotal"]["filereport"]["scan_date"], "%d/%d" % (report.pe.scan.online["virustotal"]["filereport"]["positives"], report.pe.scan.online["virustotal"]["filereport"]["total"])])
        normalizeddata = virustotaltab.get_html_string().replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>VirusTotal</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.whitelist:
        whitelisttab = PrettyTable(["Source", "Status"])
        whitelisttab.border = borderflag
        whitelisttab.header = True
        whitelisttab.padding_width = padwidth
        whitelisttab.align["Source"] = "l"
        whitelisttab.align["Status"] = "l"
        whitelisttab.add_row(["NSRL", "<span class='label label-info'>FOUND</span>" if report.pe.scan.whitelist["nsrl"] else "<span class='label label-warning'>NOTFOUND</span>"])
        whitelisttab.add_row(["Mandiant", "<span class='label label-info'>FOUND</span>" if report.pe.scan.whitelist["mandiant"] else "<span class='label label-warning'>NOTFOUND</span>"])
        normalizeddata = whitelisttab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Whitelist</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pe.scan.yara:
        yaratab = PrettyTable(["Rule", "Description", "Tags"])
        yaratab.border = borderflag
        yaratab.header = True
        yaratab.padding_width = padwidth
        yaratab.align["Rule"] = "l"
        yaratab.align["Description"] = "l"
        yaratab.align["Tags"] = "l"
        for rulename in report.pe.scan.yara.keys():
          desc = report.pe.scan.yara[rulename]["description"] if "description" in report.pe.scan.yara[rulename].keys() and report.pe.scan.yara[rulename]["description"] else ""
          tags = ", ".join(report.pe.scan.yara[rulename]["tags"]) if "tags" in report.pe.scan.yara[rulename].keys() and report.pe.scan.yara[rulename]["tags"] else ""
          yaratab.add_row([rulename, desc, tags])
        normalizeddata = yaratab.get_html_string(sortby="Rule", reversesort=False).replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Yara</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      htmldata += "%s" % (htmlends)

      thregex = re.compile(r"<tr>(\s+)<td>(.*)</td>")
      htmldata = thregex.sub(r"<tr>\1<th class='col-md-2'>\2</th>", htmldata)
      tdregex = re.compile(r"<td>(.*)</td>")
      normalizedhtmldata = tdregex.sub(r"<td class='highlight_def'>\1</td>", htmldata)

      fileutils.file_save(filename="%s/%s.html" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data="%s" % (normalizedhtmldata), mode="w")


Manager().register_plugin(pehtml)

