#!/usr/bin/env python
# Python 2 - Version 3 coming soon
# 
# Author: Wes Lambert, 3/6/2019
#
# Based off of Stephen Hosom's original bro-otx.py for integrating Alienvault OTX threat feed data with the Bro Intel Framework:
# https://github.com/hosom/bro-otx
# 
# This script leverages most of what has already been done with the original script, simply renaming many things and adapting them to fit the need for importing X-Force data.
#

import requests
import sys
import os
import json

from argparse import ArgumentParser
from ConfigParser import ConfigParser
from datetime import datetime, timedelta
from urlparse import urlparse
from requests.auth import HTTPBasicAuth

# Set up our args, etc.
parser = ArgumentParser(description='X-Force Bro Client')
parser.add_argument('-c', '--config',
                        help='configuration file path',
                        default='bro-xforce.conf')
args = parser.parse_args()
config = ConfigParser()
config.read(args.config)
key = config.get('x-force', 'apikey')
password = config.get('x-force', 'password')
auth = HTTPBasicAuth(key, password)
outfile = config.get('x-force', 'outfile')
indicator_type = config.get('x-force', 'indicator_type')
categories = config.get('x-force', 'categories')
do_notice = config.get('x-force', 'do_notice')
days = int(config.get('x-force', 'days'))
limit = str(config.get('x-force', 'results_limit')) 
ref_url = 'https://api.xforce.ibmcloud.com'
header = "#fields\tindicator\tindicator_type\tmeta.source\tmeta.url\tmeta.do_notice\n"
mtime = (datetime.now() - timedelta(days=days)).isoformat()
startDate = str(mtime)
endDate = str(datetime.now())

_map_bro_type = {
    "url": "Intel::URL",
    "ipr": "Intel::ADDR",
}

_map_key_type ={ 
     "url": "url",
     "ipr": "ip",
}

def map_bro_type(indicator_type):
    '''
    Maps an X-Force indicator type to a Bro Intel Framework type.
    '''

    return _map_bro_type.get(indicator_type)

def map_key_type(indicator_type):
    '''
    Maps an X-Force key type to use in the request URL.
    '''

    return _map_key_type.get(indicator_type)

def to_unicode(obj, encoding='utf-8'):
    if isinstance(obj, basestring):
        if not isinstance(obj, unicode):
            obj = unicode(obj, encoding)
    return obj


with open(outfile + '.tmp', 'wb') as f:
  # Write Intel file header
  f.write(header)
  # Iterate through each indicator type and write results to file
  for ind_type in json.loads(indicator_type):
    for category in json.loads(categories):
      description = 'IBM X-Force - ' + category
      url = ref_url + '/' + ind_type + '?category=' + category + '&startDate=' + startDate + '&endDate=' + endDate + '&limit=' + limit
      bro_type = map_bro_type(ind_type)
      key_type = map_key_type(ind_type)
      r = requests.get(url, auth=auth)
      if r.status_code == 400:
       continue
      result = json.loads(r.content)
      for i in result['rows']:
        fields = [to_unicode(i[key_type]),
                 to_unicode(bro_type),
                 to_unicode(description),
                 to_unicode(ref_url),
                 to_unicode(do_notice) + to_unicode('\n')]
        f.write('\t'.join(fields).encode('utf-8'))
os.rename(outfile + '.tmp', outfile)
