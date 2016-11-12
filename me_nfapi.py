from __future__ import print_function
import requests
import json
import pdb


class APISession:

    '''Class for interacting with ManageEngine Netflow Analyzer API. 
    API calls are handled with requests session object. All GETs
    against API will return JSON object to caller. 
    '''


    LISTIPGROUP_URI = '/api/json/nfaipgroup/listIPGroup'    
    ADDIPGROUP_URI = '/api/json/nfaipgroup/addIPGroup'
    LISTBILLPLAN_URI = '/api/json/nfabilling/listBillPlan'
    ADDBILLPLAN_URI = '/api/json/nfabilling/addBillPlan'
    MODIFYBILLPLAN_URI = '/api/json/nfabilling/modifyBillPlan'
    MODIFYIPGROUP_URI = '/api/json/nfaipgroup/modifyIPGroup'
    DELETEIPGROUP_URI = '/api/json/nfaipgroup/deleteIPGroup'
    DELETEBILLPLAN_URI = '/api/json/nfabilling/deleteBillPlan'
    CONVERSATION_URI = '/api/json/nfadevice/getConvData'
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

    def __init__(self, hostname, api_key, user, password, port='8080', protocol='http', timeout=30):
        
        self.hostname = hostname
        self.api_key = api_key
        self.port = port
        self.protocol = protocol
        self.user = user
        self.password = password
        self.request = requests.Session()
        self.logged_in = False
        self.NFA_SSO = None

    #=================================================================
    # Shared/General Methods
    #=================================================================

    def _get(self, uri, **kwargs):
        '''Method used for GET functions of API.'''

        #Validate session is logged in
        if not self.logged_in:
            raise Exception('Session is not logged in.')

        url = '{0:s}://{1:s}{2:s}?apiKey={3:s}'.format(
            self.protocol,
            self.hostname,
            uri,
            self.api_key
        )
        response = self.request.get(url, data = kwargs)
        return response

    def _post(self, uri, **kwargs):
        '''Method used for POST functions of API.'''

        #Validate session is logged in
        if not self.logged_in:
            raise Exception('Session is not logged in')
        
        url = '{0:s}://{1:s}{2:s}?apiKey={3:s}'.format(
            self.protocol,
            self.hostname,
            uri
        )

        #Add API key to kwargs dict
        kwargs['apiKey'] = self.api_key

        response = self.request.post(url, data=kwargs)
        return response

    def _check_required_args(self, arglist, **kwargs):
        '''Validated all required arguments for method exist.'''

        for arg in arglist:
            if not kwargs.get(arg):
                print('Missing required argument: {0}'.format(arg))
                return False
            return True

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
            encrypt_key = self.request.post(
                '{0:s}://{1:s}{2:s}'.format(
                    self.protocol,
                    self.hostname,
                    APISession.ENCRYPTED_PWORD_URI.format(self.password))
            ).text
           
            #Update cookies and headers
            self.request.cookies['domainNameForAutomaticSignIn'] = 'Authenticator'
            self.request.cookies['userNameForAutomaticSignIn'] = self.user
            self.request.cookies['signInAutomatically'] = 'True'
            self.request.cookies['authrule_name'] = 'Authenticator'
            self.request.cookies['encryptPassForAutomaticSignIn'] = encrypt_key
            self.request.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            self.request.headers['Accept-Encoding'] = 'gzip, deflate'
 
            #POST to j_security_check for auth, grab NFA_SSO value
            post_url = '{0:s}://{1:s}/j_security_check;jsessionid={2:s}'.format(
                self.protocol,
                self.hostname,
                j_session_id
            )

            post_response = self.request.post(
                post_url,
                data=APISession.AUTH_PAYLOAD.format(self.user, self.password)
            )

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


    #=================================================================
    # Feature specific methods
    #=================================================================


    def get_ip_groups(self):
    
        '''All IPGroups returned as JSON object'''
    
        response = self._get(APISession.LISTIPGROUP_URI)
        return json.loads(response.text)

    def get_bill_plans(self):

        '''All billing plans returned as JSON'''
        
        response = self._get(APISession.LISTBILLPLAN_URI)
        return json.loads(response.text)

    def add_ip_group(self, **kwargs):
        
        '''Function to add IPGroup. Takes the following case-sentive keyword arguments with example call:

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
        kwargs['apiKey'] = self.api_key
        post_url = '{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.ADDIPGROUP_URI)
        response = self.request.post(post_url, data=kwargs)
        return json.loads(response.text)
    

    def add_billing(self, **kwargs):


        '''Function to add billing group. Takes the following case-sensitve keyword arguments with example call:

        name:  (IE: 'somecompany-billing')
        desc:  (IE: 'somecompany BS')
        costUnit: (IE: 'USD')
        periodType: (IE:'monthly')
        genDate: (IE: '1')
        timezone: (IE: 'US/eastern')
        apiKey: WTF? REALLY?
        baseSpeed: (IE: '50000')
        baseCost: (IE: '500')
        addSpeed: (IE: '1')
        addCost: (IE: '600')
        type: maybe this is volume? (IE: 'speed')
        perc: 95t percentile calculation. 40 for merge, 41 for seperate (IE: '40')
        intfID: 
        ipgID: (IE: '2500033,2500027,2500034,2500025')
        bussID:
        emailID: (IE: 'someonewhocares@somecompany.com')
        emailsub: (IE: 'billing report for some crap')

        **kwargs was used so we already have a dictionary to pass for x-www-urlencoded data payload.
        '''
        
        if not self.logged_in:
            raise Exception('Session is not logged in. Call login() method to login first.')

        #Apparently this URI doesn't include API key nor does it work that way, so we have to shim 
        #the API key into our kwargs dictionary being passed as payload
        kwargs['apiKey'] = self.api_key

        #Default timezone to eastern if not already defined
        if not kwargs.get('timezone'):
            kwargs['timezone'] = 'US/Eastern'

        #Default addSpeed/addCost if not defined since it's not required
        if not kwargs.get('addSpeed'):
            kwargs['addSpeed'] = '0'
        if not kwargs.get('addCost'):
            kwargs['addCost'] = '0'

        #Adding IP group ID as required for now since there's no reason we should have a billing group not tied to an IP group
        required_args = ['name', 'desc', 'costUnit', 'periodType', 'genDate', 'timezone', 'baseSpeed', 'baseCost', 'type', 'perc', 'emailID', 'emailsub', 'ipgID'] 

        for arg in required_args:
            if not kwargs.get(arg):
                raise Exception('Missing required keyword argument for add_billing: {0:s}'.format(arg))

        #Checks passed. Formuate data paload and POST to API.
        post_url = '{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.ADDBILLPLAN_URI)
        response = self.request.post(post_url, data=kwargs)
        return json.loads(response.text)

    def modify_billing(self, **kwargs):

        '''Function to modify billing object. Looks like it takes same paramters as
        add_billing, but must also include a unique identifier 'plan id'.
        '''

        if not self.logged_in:
            raise Exception('Session is not logged in. Call login() method to login first.')

        #We should only need to check for 'planid', everything else should be provided from get_billing and passed in?
        if not kwargs.get('planid'):
            raise Exception('Missing required paramter. Billing plan identifier must be passed into modify_billing function.')

        #Modify URIs do not pass API key in URI like the get URIs do. We apparently have to pass API key in 
        #as part of url-encoded payload. 
        kwargs['apiKey'] = self.api_key

        post_url = '{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.MODIFYBILLPLAN_URI)
        response = self.request.post(post_url, data=kwargs)
        return json.loads(response.text)

    def modify_ip_group(self, **kwargs):

        '''Function to modify IPGroup object. Doesn't appear to have any unique parameters, should be able to
        query for IPGroup object with get_ip_groups, modify what we need to modify, then pass to this function 
        to udpate the existing object.
        '''
        
        if not self.logged_in:
            raise Exception('Session is not logged in. Call login() method to login first.')

        #Modify URIs do not pass API key in URI like the get URIs do. We apparently have to pass API key in 
        #as part of url-encoded payload. 
        kwargs['apiKey'] = self.api_key
        
        post_url = '{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.MODIFYIPGROUP_URI)
        response = self.request.post(post_url, data=kwargs)
        return json.loads(response.text)    

    def delete_ip_group(self, GroupName):

        '''Function to delete an IPGroup object. The only required parameter for this is GroupName.
        '''

        if not self.logged_in:
            raise Exception('Session is not logged in. Call login() method to login first.')

        payload = {}
        payload['apiKey'] = self.api_key
        payload['GroupName'] = GroupName

        post_url = '{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.DELETEIPGROUP_URI)
        response = self.request.post(post_url, data=payload)
        return json.loads(response.text)

    def delete_bill_plan(self, PlanID):

        '''Function to delete billing plan object. The format for this call is, of course, different than the others. No data is
        passed as urlencoded payload, API key and PlanID are both sent in the URI.
        '''
        
        if not self.logged_in:
            raise Exception('Session is not logged in. Call login() method to login first.')

        payload = {}
        payload['apiKey'] = self.api_key
        payload['planID'] = PlanID

        post_url = '{0:s}://{1:s}{2:s}'.format(self.protocol, self.hostname, nfapi_session.DELETEBILLPLAN_URI)
        response = self.request.post(post_url, data=payload)
        return json.loads(response.text)

    def get_group_conversation_data(self, ipgroup):

        '''Get conversation data for a specific IP group. IP group should be ID based, not
        named based. Using default params for now, will expand to include more later.
        '''

        if not self.logged_in:
            raise Exception('Session is not logged in. Call login() method to login first.')

        payload = {
            'apiKey': self.api_key,
            'DeviceID': ipgroup,
            'Count': 10,
            'Data': 'IN',
            'isNetwork': 'OFF',
            'ResolveDNS': 'false',
            'pageCount': '1',
            'expand': 'false',
            'IPGroup': 'true',
            'rows': '9',
            'TimeFrame': 'today',
            'expand': 'true'
        }
        import pdb; pdb.set_trace()
        response = self._get(APISession.CONVERSATION_URI, data=payload)
        return json.loads(response.text)
