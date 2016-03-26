__author__ = 'Andrew Crutchfield'
__version__ = '0.9'

import requests
import json
import pdb

class netflow_api:

	GET_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0",
    "Accept-Encoding": "gzip, deflate, sdch",
	"Cache-Control": "max-age=0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
	}
	LISTIPGROUP_URI = '/api/json/nfaipgroup/listIPGroup'	

	def __init__(self, hostname, api_key, user, password, port='8080', protocol='http'):
		
		self.hostname = hostname
		self.api_key = api_key
		self.port = port
		self.protocol = protocol
		self.user = user
		self.password = password
		print('Successfully initialized API object.')

	def get_ip_groups(self):
		
		full_url = '{0:2}://{1:s}{2:s}?apiKey={3:s}'.format(self.protocol, self.hostname, netflow_api.LISTIPGROUP_URI, self.api_key)
		request = requests.Session()
		request.auth = (self.user, self.password)
		request.headers = netflow_api.GET_HEADERS
		response = request.get(full_url)
		#request = requests.get(full_url, headers=netflow_api.GET_HEADERS)
		pdb.set_trace()	
