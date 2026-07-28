# Rudra: The Destroyer of Evil

Rudra tiene como objetivo proporcionar un marco de trabajo amigable para el desarrollador para el análisis exhaustivo de archivos (PCAP y PE). Proporciona funciones para escanear y generar informes que incluyen propiedades estructurales del archivo, visualización de entropía, tasa de compresión, tamaño mínimo teórico, etc. Estos detalles, junto con la información de análisis específica del formato de archivo, ayudan al analista a comprender el tipo de datos incrustados en un archivo y decidir rápidamente si merece una investigación más profunda. Admite el escaneo de archivos PE y puede realizar escaneos de API, detección de anti{debug, vm, sandbox}, detección de packers, verificación de Authenticode, además de detección de Yara, shellcode y regex sobre ellos.

## CRÉDITOS:
Rudra utiliza los siguientes módulos externos para el funcionamiento de sus diversas características. Si le resulta útil, por favor agradezca a los autores de los proyectos enumerados a continuación:

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

La publicación [Calculate File Entropy](http://www.kennethghartman.com/calculate-file-entropy/) de Kenneth Hartman también fue extremadamente útil y me inspiró a incluir estadísticas de entropía/minsize/compressionratio en los informes generados.

## LICENCIA:
Este trabajo está licenciado bajo una Licencia Creative Commons Attribution-NonCommercial-ShareAlike 4.0 Internacional.

![CC-BY-NC-SA](http://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)
