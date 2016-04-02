__author__ = 'Andrew Crutchfield'
__version__ = '0.9'

import requests
import json
import pdb

class nfapi_session:

	'''Class for interacting with ManageEngine Netflow Analyzer API. 
	API calls are handled with requests session object. All GETs
	against API will return JSON object to caller.
	'''


	LISTIPGROUP_URI = '/api/json/nfaipgroup/listIPGroup'	
	ADDIPGROUP_URI = '/api/json/nfaipgroup/addIPGroup'
	LISTBILLPLAN_URI = '/api/json/nfabilling/listBillPlan'
	LOGIN_URI = '/apiclient/ember/Login.jsp'
	ENCRYPTED_PWORD_URI = '/servlets/SettingsServlet?requestType=AJAX&EncryptPassword={0:s}&sid=0.28584800255841862'
	AUTH_PAYLOAD = 'AUTHRULE_NAME=Authenticator&clienttype=html&ScreenWidth=2272&ScreenHeight=1242&loginFromCookieData=false&ntlmv2=false&j_username={0:s}&j_password={1:s}&signInAutomatically=on&uname='
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
			encrypt_key = self.request.post('{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.ENCRYPTED_PWORD_URI.format(self.password))).text
			
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
			post_response = self.request.post(post_url, data=nfapi_session.AUTH_PAYLOAD.format(self.user, self.password))
			del self.request.headers['Content-Type']
			
			#FUTURE: Add some logic in here to make sure we've got HTTP 302 with set-cookie, verify NFA_SSO in list, etc...
			try:
				cookie_header = post_response.history[1].headers['set-cookie']
				nfa_sso_header = cookie_header.split()[3]			
				self.NFA_SSO = nfa_sso_header.split('=')[1][:-1]
				self.request.cookies['NFA__SSO'] = self.NFA_SSO
				self.logged_in = True
			except Exception as e:
				if not post_response.history:
					print('POST response history is empty. Probably failed authentication.')
				else:
					print('Unknown error trying to grab cookie data from POST response data.')
					print(e.args)

	def get_ip_groups(self):
	
		'''All IPGroups returned as JSON object'''
	
		full_url = '{0:s}://{1:s}{2:s}?apiKey={3:s}'.format(self.protocol, self.hostname, nfapi_session.LISTIPGROUP_URI, self.api_key)
		response = self.request.get(full_url)
		return json.loads(response.text)

	def get_billing(self):

		'''All billing plans returned as JSON'''
		
		full_url = '{0:s}://{1:s}{2:s}?apiKey={3:s}'.format(self.protocol, self.hostname, nfapi_session.LISTBILLPLAN_URI, self.api_key)
		response = self.request.get(full_url)
		return json.loads(response.text)

	def add_ip_group(self, **kwargs):
		
		'''Function to add IPGroup. Takes the following keyword arguments with example call:

		GroupName: String of group name (IE: 'test-group')
		Desc: Description for IP Group (IE: 'Test group for python docstring')
		speed: Speed in bits per second (IE: '50000')
		DevList: List of interfaces/devices tied to IP Group. Value of -1 means all. 
		status: Type of IP data being added to group, IE: include/exclude/between sites (IE: 'include,include,include')
		IPData: List of IP Data seperated by comma. Can be combination of addresses, ranges, or sites. (IE: '8.8.8.8-8.8.4.4-1.1.1.0,255.255.255.0')
		IPType: List of IP types seperate by comman, Can be combination of ipaddress, iprange, ipnetwork. (IE: 'ipaddress,ipaddress,ipnetwork')
		ToIPType: Looks like this is only used for status type of 'between' and is the  definition of the remote endpoint in between definition. Should
				  take same values as IPType. 
		
		**kwargs was used so we already have a dictionary to pass for x-www-urlencoded data payload. 
		'''

		#Make sure session is logged in or else POST will fail.
		if not self.logged_in:
			raise Exception('Session is not logged in. Call login() method to login first.')

		#Make sure we have received legitimate keyword arguments. These will be NoneType if not passed properly. Maybe we can change this to comprehension later....
		required_args = ['GroupName', 'Desc', 'speed', 'DevList', 'status', 'IPData', 'IPType']

		for arg in required_args:
			if not kwargs.get(arg):
				raise Exception('Missing required keywoard argument for add_ip_group: {0:s}'.format(arg))

		#Checks passed. Formulate data payload and POST to API. 
		pdb.set_trace()
		post_url = '{0:s}://{1:s}{2:s}?apiKey={3:s}'.format(self.protocol, self.hostname, nfapi_session.ADDIPGROUP_URI, self.api_key)
		response = self.request.post(post_url, data=kwargs)
		
		#Validate response
		if 'Group name already exists' in response.text:
			pass #ADD SOME LOGGING HERE
		#NEED ADDITIONAL INTERNAL SERVER ERROR CHECKING RIGHT HERE
		if response.status_code == 200 and 'IPGroup added successfully' in response.text:
			#WE'RE GOOD. ADD LOGGING STATEMENT HERE
			return True	