from jinja2 import Environment
from jinja2 import FileSystemLoader

from aayudh import utils

import logging.config
import base64
import json
import os


def hexdump(data, dataoffset=0, length=16, sep='.'):
  return utils.hexdump(data, dataoffset, length, sep)


def from_base64(data):
  return base64.b64decode(data)


class Report:
  def __init__(self):
    self.logger = logging.getLogger(__name__)

    self.json_report = None
    self.html_report = None


  def generate_report(self, session):
    # check if report dir exists, else create it
    # http://stackoverflow.com/questions/273192/in-python-check-if-a-directory-exists-and-create-it-if-necessary
    if not os.path.exists(session['config']['reports_dir']):
      os.makedirs(session['config']['reports_dir'])

    # generate json report
    self.json_report = '%s/%s.json' % (session['config']['reports_dir'], session['report']['filestats']['hashes']['sha256'])
    open(self.json_report, 'w').write(json.dumps(session['report'], sort_keys=True).encode('utf-8'))

    # generate html report
    if "html" in session['config']['reports_type']:
      self.html_report = '%s/%s.html' % (session['config']['reports_dir'], session['report']['filestats']['hashes']['sha256'])

      env = Environment(loader=FileSystemLoader(os.path.dirname(os.path.abspath(__file__))), trim_blocks=True, lstrip_blocks=True)
      env.filters['base64_decode'] = from_base64
      env.filters['hexdump'] = hexdump

      template = env.get_template(session['config']['html_template_pcap'])
      with open(self.html_report, 'w') as htmlfile:
        output = template.render(session=session)

        htmlfile.write(output.encode('utf-8'))

    # generate pdf report
    session['config']['reports_type'] = ['html']
    if "pdf" in session['config']['reports_type']:
      self.pdf_report = '%s/%s.pdf' % (session['config']['reports_dir'], session['report']['filestats']['hashes']['sha256'])

      print type(session['report']['filestats']['filename_absolute']), session['report']['filestats']['filename_absolute']
      utils.file_to_pdf(session['report']['filestats']['filename_absolute'])
