from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import json
import sys
import re
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class pcaphtml(PluginInterface):
  name = "pcaphtml"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Dump the summary of Pcap analysis as HTML"
    self.details.mimetypes = ["application/vnd.tcpdump.pcap"]
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
      normalizeddata = hashtab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Hashes</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
      htmldata += "%s\n" % (normalizeddata)

      # show pcap stats
      if report.pcap.parsed.stats:
        statstab = PrettyTable(["Attribute", "Value"])
        statstab.border = borderflag
        statstab.header = headerflag
        statstab.padding_width = padwidth
        statstab.align["Attribute"] = "l"
        statstab.align["Value"] = "l"
        statstab.add_row(["Magic", report.pcap.parsed.stats["pcapmagic"]])
        statstab.add_row(["Encapsulation", report.pcap.parsed.stats["pcapencapsulation"]])
        statstab.add_row(["Snaplen", report.pcap.parsed.stats["snaplen"]])
        statstab.add_row(["Starttime", report.pcap.parsed.stats["capturestarttime"]])
        statstab.add_row(["Endtime", report.pcap.parsed.stats["captureendtime"]])
        statstab.add_row(["Duration", report.pcap.parsed.stats["captureduration"]])
        statstab.add_row(["Bitrate", report.pcap.parsed.stats["bitrate"]])
        statstab.add_row(["Byterate", report.pcap.parsed.stats["byterate"]])
        statstab.add_row(["Bytescount", report.pcap.parsed.stats["bytescount"]])
        statstab.add_row(["Packetscount", report.pcap.parsed.stats["packetscount"]])
        statstab.add_row(["Packetrate (avg.)", report.pcap.parsed.stats["avgpacketrate"]])
        statstab.add_row(["Packetsize (avg.)", report.pcap.parsed.stats["avgpacketsize"]])
        normalizeddata = statstab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Pcap Stats</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      if report.pcap.parsed.counts:
        countstab = PrettyTable(["Protocol/Direction", "Bytes", "Packets", "Bytes/Packet"])
        countstab.border = borderflag
        countstab.header = headerflag
        countstab.header = True
        countstab.padding_width = padwidth
        countstab.align["Protocol/Direction"] = "l"
        countstab.align["Bytes"] = "l"
        countstab.align["Packets"] = "l"
        countstab.align["Bytes/Packet"] = "l"
        countstab.add_row(["CTS", report.pcap.parsed.counts["ctsbytes"], report.pcap.parsed.counts["ctspackets"], report.pcap.parsed.counts["ctsbytesperpacket"]])
        countstab.add_row(["STC", report.pcap.parsed.counts["stcbytes"], report.pcap.parsed.counts["stcpackets"], report.pcap.parsed.counts["stcbytesperpacket"]])
        countstab.add_row(["TCP", report.pcap.parsed.counts["tcpbytes"], report.pcap.parsed.counts["tcppackets"], report.pcap.parsed.counts["tcpbytesperpacket"]])
        countstab.add_row(["UDP", report.pcap.parsed.counts["udpbytes"], report.pcap.parsed.counts["udppackets"], report.pcap.parsed.counts["udpbytesperpacket"]])
        normalizeddata = countstab.get_html_string().replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Proto Stats</strong></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>")
        htmldata += "%s\n" % (normalizeddata)

      # show pcap hosts
      if report.pcap.parsed.hosts:
        hosttab = PrettyTable(["Attribute", "Value"])
        hosttab.border = borderflag
        hosttab.header = headerflag
        hosttab.padding_width = padwidth
        hosttab.align["Attribute"] = "l"
        hosttab.align["Value"] = "l"
        for idx, host in enumerate(report.pcap.parsed.hosts):
          hosttab.add_row(["<span class='badge'>#%d</span>  %s" % (idx+1, host), ""])
          if "geo" in report.pcap.parsed.hosts[host] and report.pcap.parsed.hosts[host]["geo"]:
            if report.pcap.parsed.hosts[host]["geo"]["time_zone"]:
              hosttab.add_row(["Timezone", report.pcap.parsed.hosts[host]["geo"]["time_zone"]])
            if report.pcap.parsed.hosts[host]["geo"]["latitude"] and report.pcap.parsed.hosts[host]["geo"]["longitude"]:
              # https://www.google.com/maps?ll=lat,lon&z=5
              hosttab.add_row(["Lat/Lon", "<a href='https://www.google.com/maps/preview/@%s,%s,6z'>%s/%s</a>" % (report.pcap.parsed.hosts[host]["geo"]["latitude"], report.pcap.parsed.hosts[host]["geo"]["longitude"], report.pcap.parsed.hosts[host]["geo"]["latitude"], report.pcap.parsed.hosts[host]["geo"]["longitude"])])
            loclist = []
            if report.pcap.parsed.hosts[host]["geo"]["city"]:
              loclist.append(report.pcap.parsed.hosts[host]["geo"]["city"])
            if report.pcap.parsed.hosts[host]["geo"]["region_name"]:
              loclist.append(report.pcap.parsed.hosts[host]["geo"]["region_name"])
            if report.pcap.parsed.hosts[host]["geo"]["country_name"]:
              loclist.append(report.pcap.parsed.hosts[host]["geo"]["country_name"])
            hosttab.add_row(["Location", ", ".join(loclist)])
          if "whois" in report.pcap.parsed.hosts[host] and report.pcap.parsed.hosts[host]["whois"]:
            if report.pcap.parsed.hosts[host]["whois"]["asn"]:
              hosttab.add_row(["ASN", "<a href='http://bgp.he.net/AS%s'>AS%s</a>" % (report.pcap.parsed.hosts[host]["whois"]["asn"], report.pcap.parsed.hosts[host]["whois"]["asn"])])
            if report.pcap.parsed.hosts[host]["whois"]["asn_registry"]:
              hosttab.add_row(["Registry", report.pcap.parsed.hosts[host]["whois"]["asn_registry"]])
            if report.pcap.parsed.hosts[host]["whois"]:
              hosttab.add_row(["Whois", "<pre class='scroll_def'>%s</pre>" % json.dumps(report.pcap.parsed.hosts[host]["whois"], sort_keys=True, indent=2)])
            if report.pcap.parsed.hosts[host]["rdns"]:
              hosttab.add_row(["RDNS", "<pre class='scroll_def'>%s</pre>" % json.dumps(report.pcap.parsed.hosts[host]["rdns"], sort_keys=True, indent=2)])
          hosttab.add_row(["", ""])
        normalizeddata = hosttab.get_html_string().replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Host Stats</strong> <span class='badge'>%d</span></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>" % (len(report.pcap.parsed.hosts)))
        htmldata += "%s\n" % (normalizeddata)

      # show pcap flows
      if report.pcap.parsed.flows:
        flowtab = PrettyTable(["Flow", "Details"])
        flowtab.border = borderflag
        flowtab.header = headerflag
        flowtab.padding_width = padwidth
        flowtab.align["Attribute"] = "l"
        flowtab.align["Value"] = "l"
        for idx, flow in enumerate(report.pcap.parsed.flows):
          if ("ctsbuf" in flow["protobuf"] and flow["protobuf"]["ctsbuf"]) or ("stcbuf" in flow["protobuf"] and flow["protobuf"]["stcbuf"]):
            srcip, srcport, dstip, dstport = flow["srcip"], flow["srcport"], flow["dstip"],flow["dstport"]
            if flow["l7protocol"]:
              flowtab.add_row(["<span class='badge'>#%d</span>  %s:%s - %s:%s (%s/%s)" % (idx+1, srcip, srcport, dstip, dstport, flow["l7protocol"], flow["l4protocol"]), ""])
            else:
              flowtab.add_row(["<span class='badge'>#%d</span>  %s:%s - %s:%s (%s)" % (idx+1, srcip, srcport, dstip, dstport, flow["l4protocol"]), ""])

            if flow["stats"]:
              if "cts" in flow["stats"] and flow["stats"]["cts"]:
                if flow["stats"]["cts"]["entropycategory"] in ["SUSPICIOUS", "NATIVE-PACKED", "PACKED", "PACKED-COMPRESSED", "COMPRESSED", "COMPRESSED-ENCRYPTED", "ENCRYPTED"]:
                  flowtab.add_row(["CTS Stats", "<span class='label label-info'>SIZE: %d</span> <span class='label label-info'>MINSIZE: %s</span> <span class='label label-info'>CR: %s%%</span> <span class='label label-warning'>H: %s %s</span>" % (flow["stats"]["cts"]["datasizeinbytes"], flow["stats"]["cts"]["mindatasize"], flow["stats"]["cts"]["compressionratio"], flow["stats"]["cts"]["entropy"], flow["stats"]["cts"]["entropycategory"])])
                else:
                  flowtab.add_row(["CTS Stats", "<span class='label label-info'>SIZE: %d</span> <span class='label label-info'>MINSIZE: %s</span> <span class='label label-info'>CR: %s%%</span> <span class='label label-info'>H: %s %s</span>" % (flow["stats"]["cts"]["datasizeinbytes"], flow["stats"]["cts"]["mindatasize"], flow["stats"]["cts"]["compressionratio"], flow["stats"]["cts"]["entropy"], flow["stats"]["cts"]["entropycategory"])])
            if flow["l7protocol"] == "HTTP" and flow["l7protocoldecode"]:
              if flow["l7protocoldecode"]["request"]:
                body = None
                if flow["l7protocoldecode"]["request"]["body"]:
                  body = "\n\n%s" % utils.hexdump(flow["l7protocoldecode"]["request"]["body"][:report.misc.config.htmlhexdumpbytes])
                headers = []
                for header in flow["l7protocoldecode"]["request"]["headers"]:
                  headers.append("%s: %s" % (header.title(), flow["l7protocoldecode"]["request"]["headers"][header]))
                if body:
                  flowtab.add_row(["HTTP Request", "<pre class='scroll_cts'>%s %s HTTP/%s\n%s%s</pre>" % (flow["l7protocoldecode"]["request"]["method"], flow["l7protocoldecode"]["request"]["uri"], flow["l7protocoldecode"]["request"]["version"], "\n".join(headers), body.replace("<", "&lt;").replace(">", "&gt;").replace("&amp;", "&"))])
                else:
                  flowtab.add_row(["HTTP Request", "<pre class='scroll_cts'>%s %s HTTP/%s\n%s</pre>" % (flow["l7protocoldecode"]["request"]["method"], flow["l7protocoldecode"]["request"]["uri"], flow["l7protocoldecode"]["request"]["version"], "\n".join(headers))])
            elif report.misc.config.enablebufhexdump:
              if "ctsbuf" in flow["protobuf"] and flow["protobuf"]["ctsbuf"]:
                flowtab.add_row(["Hexdump", "<pre class='scroll_cts'>%s</pre>" % utils.hexdump(flow["protobuf"]["ctsbuf"][:report.misc.config.htmlhexdumpbytes]).replace("<", "&lt;").replace(">", "&gt;").replace("&amp;", "&")])

            if flow["scan"]["shellcode"]:
              if "cts" in flow["scan"]["shellcode"] and flow["scan"]["shellcode"]["cts"]:
                flowtab.add_row(["CTS Shellcode", "<pre class='scroll_stc'>%s</pre>" % flow["scan"]["shellcode"]["cts"]["profile"]])
            if flow["scan"]["yara"]:
              if "cts" in flow["scan"]["yara"] and flow["scan"]["yara"]["cts"]:
                ctsmatches = []
                for entry in flow["scan"]["yara"]["cts"]:
                  ctsmatches.append(entry["rule"])
                flowtab.add_row(["CTS Yara Matches", "\n".join(ctsmatches)])

            if flow["stats"]:
              if "stc" in flow["stats"] and flow["stats"]["stc"]:
                if flow["stats"]["stc"]["entropycategory"] in ["SUSPICIOUS", "NATIVE-PACKED", "PACKED", "PACKED-COMPRESSED", "COMPRESSED", "COMPRESSED-ENCRYPTED", "ENCRYPTED"]:
                  flowtab.add_row(["STC Stats", "<span class='label label-info'>SIZE: %d</span> <span class='label label-info'>MINSIZE: %s</span> <span class='label label-info'>CR: %s%%</span> <span class='label label-warning'>H: %s %s</span>" % (flow["stats"]["stc"]["datasizeinbytes"], flow["stats"]["stc"]["mindatasize"], flow["stats"]["stc"]["compressionratio"], flow["stats"]["stc"]["entropy"], flow["stats"]["stc"]["entropycategory"])])
                else:
                  flowtab.add_row(["STC Stats", "<span class='label label-info'>SIZE: %d</span> <span class='label label-info'>MINSIZE: %s</span> <span class='label label-info'>CR: %s%%</span> <span class='label label-info'>H: %s %s</span>" % (flow["stats"]["stc"]["datasizeinbytes"], flow["stats"]["stc"]["mindatasize"], flow["stats"]["stc"]["compressionratio"], flow["stats"]["stc"]["entropy"], flow["stats"]["stc"]["entropycategory"])])
            if flow["l7protocol"] == "HTTP" and flow["l7protocoldecode"]:
              if flow["l7protocoldecode"]["response"]:
                body = None
                if flow["l7protocoldecode"]["response"]["body"]:
                  body = "\n\n%s" % utils.hexdump(flow["l7protocoldecode"]["response"]["body"][:report.misc.config.htmlhexdumpbytes])
                headers = []
                for header in flow["l7protocoldecode"]["response"]["headers"]:
                  headers.append("%s: %s" % (header.title(), flow["l7protocoldecode"]["response"]["headers"][header]))
                if body:
                  flowtab.add_row(["HTTP Response", "<pre class='scroll_stc'>HTTP/%s %s %s\n%s%s</pre>" % (flow["l7protocoldecode"]["response"]["version"], flow["l7protocoldecode"]["response"]["status"], flow["l7protocoldecode"]["response"]["reason"], "\n".join(headers), body.replace("<", "&lt;").replace(">", "&gt;").replace("&amp;", "&"))])
                else:
                  flowtab.add_row(["HTTP Response", "<pre class='scroll_stc'>HTTP/%s %s %s\n%s</pre>" % (flow["l7protocoldecode"]["response"]["version"], flow["l7protocoldecode"]["response"]["status"], flow["l7protocoldecode"]["response"]["reason"], "\n".join(headers))])
            elif report.misc.config.enablebufhexdump:
              if "stcbuf" in flow["protobuf"] and flow["protobuf"]["stcbuf"]:
                flowtab.add_row(["Hexdump", "<pre class='scroll_stc'>%s</pre>" % utils.hexdump(flow["protobuf"]["stcbuf"][:report.misc.config.htmlhexdumpbytes]).replace("<", "&lt;").replace(">", "&gt;").replace("&amp;", "&")])

            if flow["scan"]["shellcode"]:
              if "stc" in flow["scan"]["shellcode"] and flow["scan"]["shellcode"]["stc"]:
                flowtab.add_row(["STC Shellcode", "<pre class='scroll_stc'>%s</pre>" % flow["scan"]["shellcode"]["stc"]["profile"]])
            if flow["scan"]["yara"]:
              if "stc" in flow["scan"]["yara"] and flow["scan"]["yara"]["stc"]:
                stcmatches = []
                for entry in flow["scan"]["yara"]["stc"]:
                  stcmatches.append(entry["rule"])
                flowtab.add_row(["STC Yara Matches", "\n".join(stcmatches)])
            flowtab.add_row(["", ""])

          elif "udpbuf" in flow["protobuf"] and flow["protobuf"]["udpbuf"]:
            srcip, srcport, dstip, dstport = flow["srcip"], flow["srcport"], flow["dstip"],flow["dstport"]
            if flow["l7protocol"]:
              flowtab.add_row(["<span class='badge'>#%d</span>  %s:%s - %s:%s (%s/%s)" % (idx+1, srcip, srcport, dstip, dstport, flow["l7protocol"], flow["l4protocol"]), ""])
            else:
              flowtab.add_row(["<span class='badge'>#%d</span>  %s:%s - %s:%s (%s)" % (idx+1, srcip, srcport, dstip, dstport, flow["l4protocol"]), ""])
            flowtab.add_row(["Hexdump", "<pre class='scroll_def'>%s</pre>" % utils.hexdump(flow["protobuf"]["udpbuf"][:report.misc.config.htmlhexdumpbytes]).replace("<", "&lt;").replace(">", "&gt;").replace("&amp;", "&")])
            flowtab.add_row(["ProtoDecode", "<pre class='scroll_def'>%s</pre>" % json.dumps(flow["l7protocoldecode"], sort_keys=True, indent=2).decode("windows-1252").encode("ascii","ignore")])

        normalizeddata = flowtab.get_html_string().replace("<br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>", "").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("</table>", "</table></div></div></div></div>").replace("<table>", "<div class='panel panel-info'>\n<div class='panel-heading'><strong>Flow Stats</strong> <span class='badge'>%d</span></div>\n<div class='panel-body'>\n<div class='row'>\n<div class='col-md-12'>\n<table class='table table-condensed table-hover table-striped'>" % (len(report.pcap.parsed.flows)), 1)
        htmldata += "%s\n" % (normalizeddata)

      htmldata += "%s" % (htmlends)

      thregex = re.compile(r"<tr>(\s+)<td>(.*)</td>")
      htmldata = thregex.sub(r"<tr>\1<th class='col-md-2'>\2</th>", htmldata)
      tdregex = re.compile(r"<td>(.*)</td>")
      normalizedhtmldata = tdregex.sub(r"<td class='highlight_def'>\1</td>", htmldata)

      fileutils.file_save(filename="%s/%s.html" % (report.misc.config.currreportpath, report.misc.config.currreportfile), data="%s" % (normalizedhtmldata), mode="w")


Manager().register_plugin(pcaphtml)

