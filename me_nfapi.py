__author__ = 'Andrew Crutchfield'
__version__ = '0.9'

import requests
import json
import pdb

class netflow_api:

	LISTIPGROUP_URI = '/api/json/nfaipgroup/listIPGroup'	
	LOGIN_URI = '/apiclient/ember/Login.jsp'
	ENCRYPTED_PWORD_URI = '/servlets/SettingsServlet?requestType=AJAX&EncryptPassword=admin&sid=0.28584800255841862'
	AUTH_PAYLOAD = 'AUTHRULE_NAME=Authenticator&clienttype=html&ScreenWidth=2272&ScreenHeight=1242&loginFromCookieData=false&ntlmv2=false&j_username=admin&j_password=admin&signInAutomatically=on&uname='
	GET_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:20.0) Gecko/20100101 Firefox/20.0",
    "Accept-Encoding": "gzip, deflate, sdch",
	"Cache-Control": "max-age=0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive",
	}

	def __init__(self, hostname, api_key, user, password, port='8080', protocol='http'):
		
		self.hostname = hostname
		self.api_key = api_key
		self.port = port
		self.protocol = protocol
		self.user = user
		self.password = password
		self.request = requests.Session()
		self.logged_in = False
		self.NFA_SSO = None
		print('Successfully initialized API object.')

	def login(self):

		'''Create requests session object, modify it's cookie/header
		content, log in to API and retrieve NFA_SSO token
		to be used for all functions
		'''

		if self.logged_in:
			print('User is already logged in')
		else:
			
			#Load home page for cookie/referrer reasons, grab encrypted key
			home_page = self.request.get('{0:s}://{1:s}'.format(self.protocol, self.hostname))
			j_session_id = home_page.cookies['JSESSIONID']
			encrypt_key = self.request.post('{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, netflow_api.ENCRYPTED_PWORD_URI)).text
			
			#Update cookies and headers
			self.request.cookies['domainNameForAutomaticSignIn'] = 'Authenticator'
			self.request.cookies['userNameForAutomaticSignIn'] = self.user
			self.request.cookies['signInAutomatically'] = 'True'
			self.request.cookies['authrule_name'] = 'Authenticator'
			self.request.cookies['encryptPassForAutomaticSignIn'] = encrypt_key
			self.request.headers['Content-Type'] = 'application/x-www-form-urlencoded'
			self.request.headers['Accept-Encoding'] = 'gzip, deflate'
			
			#POST to j_security_check for auth, grab NFA_SSO value
			post_url = '{0:s}://{1:s}/j_security_check;jsessionid={2:s}'.format(self.protocol, self.hostname, j_session_id)
			post_response = self.request.post(post_url, data=netflow_api.AUTH_PAYLOAD)
			del self.request.headers['Content-Type']

			#FUTURE: Add some logic in here to make sure we've got HTTP 302 with set-cookie, verify NFA_SSO in list, etc...
			cookie_header = post_response.history[1].headers['set-cookie']
			nfa_sso_header = cookie_header.split()[3]			
			self.NFA_SSO = nfa_sso_header.split('=')[1][:-1]
			self.request.cookies['NFA__SSO'] = self.NFA_SSO

			#Finally, set logged_in attribute to True
			self.logged_in = True

	def get_ip_groups(self):
		
		full_url = '{0:s}://{1:s}{2:s}?apiKey={3:s}'.format(self.protocol, self.hostname, netflow_api.LISTIPGROUP_URI, self.api_key)
		response = self.request.get(full_url)
		return response.text
