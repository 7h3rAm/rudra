from lib.external.PluginManager import PluginInterface, Manager
from prettytable import PrettyTable
from aayudh import utils, fileutils

import sys
import os


current_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.normpath(os.path.join(current_dir, ".."))
sys.path.insert(0, root_dir)


class pcapsummary(PluginInterface):
  name = "pcapsummary"
  enabled = True

  def __init__(self):
    self.details = utils.objdict({})
    self.details.name = self.name
    self.details.description = "Display a summary of Pcap analysis"
    self.details.mimetypes = ["application/vnd.tcpdump.pcap"]
    self.details.author = "@7h3rAm"
    self.details.version = "0.01"
    self.details.date = "02/NOV/2015"
    self.details.path = ("" if __file__ is None else os.path.abspath(__file__))

  def run(self, report):
    if self.details["mimetypes"] and report.meta.filemimetype in self.details["mimetypes"]:
      borderflag = False
      headerflag = False
      padwidth = 1

      summarytab = PrettyTable(["Attribute", "Value"])
      summarytab.border = borderflag
      summarytab.header = headerflag
      summarytab.padding_width = padwidth
      summarytab.align["Attribute"] = "l"
      summarytab.align["Value"] = "l"

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
      result = statstab.get_string()
      if result != "":
        summarytab.add_row(["Stats", result])
        summarytab.add_row(["", ""])

      if report.pcap.parsed.counts:
        countstab = PrettyTable(["Attribute", "Value"])
        countstab.border = borderflag
        countstab.header = headerflag
        countstab.padding_width = padwidth
        countstab.align["Attribute"] = "l"
        countstab.align["Value"] = "l"
        countstab.add_row(["CTS Bytes", report.pcap.parsed.counts["ctsbytes"]])
        countstab.add_row(["CTS Packets", report.pcap.parsed.counts["ctspackets"]])
        countstab.add_row(["CTS Bytes/Packet", report.pcap.parsed.counts["ctsbytesperpacket"]])
        countstab.add_row(["", ""])
        countstab.add_row(["STC Bytes", report.pcap.parsed.counts["stcbytes"]])
        countstab.add_row(["STC Packets", report.pcap.parsed.counts["stcpackets"]])
        countstab.add_row(["STC Bytes/Packet", report.pcap.parsed.counts["stcbytesperpacket"]])
        countstab.add_row(["", ""])
        countstab.add_row(["TCP Bytes", report.pcap.parsed.counts["tcpbytes"]])
        countstab.add_row(["TCP Packets", report.pcap.parsed.counts["tcppackets"]])
        countstab.add_row(["TCP Bytes/Packet", report.pcap.parsed.counts["tcpbytesperpacket"]])
        countstab.add_row(["", ""])
        countstab.add_row(["UDP Bytes", report.pcap.parsed.counts["udpbytes"]])
        countstab.add_row(["UDP Packets", report.pcap.parsed.counts["udppackets"]])
        countstab.add_row(["UDP Bytes/Packet", report.pcap.parsed.counts["udpbytesperpacket"]])
      result = countstab.get_string()
      if result != "":
        summarytab.add_row(["Counts", result])
        summarytab.add_row(["", ""])

      # show pcap hosts
      if report.pcap.parsed.hosts:
        hosttab = PrettyTable(["Attribute", "Value"])
        hosttab.border = borderflag
        hosttab.header = headerflag
        hosttab.padding_width = padwidth
        hosttab.align["Attribute"] = "l"
        hosttab.align["Value"] = "l"
        for host in report.pcap.parsed.hosts:
          hosttab.add_row([host, ""])
          if hasattr(report.pcap.parsed.hosts[host], "geo") and report.pcap.parsed.hosts[host].geo:
            if report.pcap.parsed.hosts[host]["geo"]["time_zone"]:
              hosttab.add_row(["Timezone", report.pcap.parsed.hosts[host]["geo"]["time_zone"]])
            if report.pcap.parsed.hosts[host]["geo"]["latitude"] and report.pcap.parsed.hosts[host]["geo"]["longitude"]:
              hosttab.add_row(["Lat/Lon", "%s/%s" % (report.pcap.parsed.hosts[host]["geo"]["latitude"], report.pcap.parsed.hosts[host]["geo"]["longitude"])])
            loclist = []
            if report.pcap.parsed.hosts[host]["geo"]["city"]:
              loclist.append(report.pcap.parsed.hosts[host]["geo"]["city"])
            if report.pcap.parsed.hosts[host]["geo"]["region_name"]:
              loclist.append(report.pcap.parsed.hosts[host]["geo"]["region_name"])
            if report.pcap.parsed.hosts[host]["geo"]["country_name"]:
              loclist.append(report.pcap.parsed.hosts[host]["geo"]["country_name"])
            hosttab.add_row(["Location", ", ".join(loclist)])
          if hasattr(report.pcap.parsed.hosts[host], "whois") and report.pcap.parsed.hosts[host].whois:
            if report.pcap.parsed.hosts[host].whois["asn"]:
              hosttab.add_row(["ASN", "AS%s" % report.pcap.parsed.hosts[host].whois["asn"]])
            if report.pcap.parsed.hosts[host].whois["asn_registry"]:
              hosttab.add_row(["Registry", report.pcap.parsed.hosts[host].whois["asn_registry"]])
          hosttab.add_row(["", ""])
        result = hosttab.get_string()
        if result != "":
          summarytab.add_row(["Hosts", result])

      # show pcap flows
      if report.pcap.parsed.flows:
        flowtab = PrettyTable(["Attribute", "Value"])
        flowtab.border = borderflag
        flowtab.header = headerflag
        flowtab.padding_width = padwidth
        flowtab.align["Attribute"] = "l"
        flowtab.align["Value"] = "l"
        for flow in report.pcap.parsed.flows:
          srcip, srcport, dstip, dstport = flow["srcip"], flow["srcport"], flow["dstip"],flow["dstport"]
          if flow["l7protocol"]:
            flowtab.add_row(["%s:%s - %s:%s (%s/%s)" % (srcip, srcport, dstip, dstport, flow["l7protocol"], flow["l4protocol"]), ""])
          else:
            flowtab.add_row(["%s:%s - %s:%s (%s)" % (srcip, srcport, dstip, dstport, flow["l4protocol"]), ""])
          if flow["stats"]:
            if hasattr(flow["stats"], "cts") and flow["stats"]["cts"]:
              flowtab.add_row(["CTS Size", flow["stats"]["cts"]["datasizeinbytes"]])
              flowtab.add_row(["CTS Minsize", "%s (%s%%)" % (flow["stats"]["cts"]["mindatasize"], flow["stats"]["cts"]["compressionratio"])])
              flowtab.add_row(["CTS Entropy", "%s (%s)" % (flow["stats"]["cts"]["entropy"], flow["stats"]["cts"]["entropycategory"])])
            if hasattr(flow["stats"], "stc") and flow["stats"]["stc"]:
              flowtab.add_row(["STC Size", flow["stats"]["stc"]["datasizeinbytes"]])
              flowtab.add_row(["STC Minsize", "%s (%s%%)" % (flow["stats"]["stc"]["mindatasize"], flow["stats"]["stc"]["compressionratio"])])
              flowtab.add_row(["STC Entropy", "%s (%s)" % (flow["stats"]["stc"]["entropy"], flow["stats"]["stc"]["entropycategory"])])
            flowtab.add_row(["", ""])

          if flow["scan"]["shellcode"]:
            if hasattr(flow["scan"]["shellcode"], "cts") and flow["scan"]["shellcode"]["cts"]:
              flowtab.add_row(["CTS Shellcode Offset", "0x%x" % flow["scan"]["shellcode"]["cts"]["offset"]])
              flowtab.add_row(["CTS Shellcode Profile", "%s" % flow["scan"]["shellcode"]["cts"]["profile"]])
            if hasattr(flow["scan"]["shellcode"], "stc") and flow["scan"]["shellcode"]["stc"]:
              flowtab.add_row(["STC Shellcode Offset", "0x%x" % flow["scan"]["shellcode"]["stc"]["offset"]])
              flowtab.add_row(["STC Shellcode Profile", "%s" % flow["scan"]["shellcode"]["stc"]["profile"]])
            flowtab.add_row(["", ""])

          if flow["scan"]["yara"]:
            if hasattr(flow["scan"]["yara"], "cts") and flow["scan"]["yara"]["cts"]:
              ctsmatches = []
              for entry in flow["scan"]["yara"]["cts"]:
                ctsmatches.append(entry["rule"])
              flowtab.add_row(["CTS Yara Matches", "\n".join(ctsmatches)])
            if hasattr(flow["scan"]["yara"], "stc") and flow["scan"]["yara"]["stc"]:
              stcmatches = []
              for entry in flow["scan"]["yara"]["stc"]:
                stcmatches.append(entry["rule"])
              flowtab.add_row(["STC Yara Matches", "\n".join(stcmatches)])
            flowtab.add_row(["", ""])

        result = flowtab.get_string()
        if result != "":
          summarytab.add_row(["Flows", result])

      result = summarytab.get_string()
      if result != "":
        print "\nPcap Summary:\n%s" % (result)


Manager().register_plugin(pcapsummary)

