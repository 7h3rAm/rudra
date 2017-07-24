# Rudra: The Destroyer of Evil

Rudra aims to provide a developer-friendly framework for exhaustive analysis of (PCAP and PE) files. It provides features to scan and generate reports that include file's structural properties, entropy visualization, compression ratio, theoretical minsize, etc. These details, alongwith file-format specific analysis information, help an analyst to understand the type of data embedded in a file and quickly decide if it deserves further investigation. It supports scanning PE files and can perform API scans, anti{debug, vm, sandbox} detection, packer detection, authenticode verification, alongwith Yara, shellcode, and regex detection upon them.

## CREDITS:
Rudra uses following external modules for its various features to work. If you find it useful, please thank authors of the below listed projects:

* [libnids](http://libnids.sourceforge.net/)/[pynids](http://jon.oberheide.org/pynids/)
* [libdasm](https://github.com/jtpereyda/libdasm)/[pydasm](https://github.com/jtpereyda/libdasm/tree/master/pydasm)
* [libemu](http://libemu.carnivore.it/)/[pylibemu](https://github.com/buffer/pylibemu)
* [utilitybelt](https://github.com/yolothreat/utilitybelt)
* [XRayGlasses](https://github.com/Xen0ph0n/XRayGlasses)
* [python-magic](https://github.com/ahupp/python-magic)
* [ssdeep](http://ssdeep.sourceforge.net/)/[pydeep](https://github.com/kbandla/pydeep)
* [ipwhois](https://github.com/secynic/ipwhois)
* [requests](http://docs.python-requests.org/en/latest/)
* [GeoIP](https://pypi.python.org/pypi/pygeoip/)
* [pygeoip](https://pypi.python.org/pypi/pygeoip)
* [prettytable](https://pypi.python.org/pypi/PrettyTable)
* [jinja2](https://pypi.python.org/pypi/Jinja2)

The [Calculate File Entropy](http://www.kennethghartman.com/calculate-file-entropy/) post by Kenneth Hartman was also extremely helpful and it inspired me to include entropy/minsize/compressionratio statistics in generated reports.

## LICENSE:
This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.

![CC-BY-NC-SA](http://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)
