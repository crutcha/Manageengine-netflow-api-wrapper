from __future__ import print_function
from .ipgroup import IPGroup, IPRange, IPNetwork
from .billing import BillPlan
from .device import Device
import requests
import json
import random

class NFApi:

    '''Class for interacting with ManageEngine Netflow Analyzer API. 
    API calls are handled with requests session object. All GETs
    against API will return JSON object to caller. 
    '''

    #API URIs
    LISTIPGROUP_URI = '/api/json/nfaipgroup/listIPGroup'    
    ADDIPGROUP_URI = '/api/json/nfaipgroup/addIPGroup'
    LISTBILLPLAN_URI = '/api/json/nfabilling/listBillPlan'
    LISTDEVLIST_URI = '/api/json/nfadevice/listDevForMultiSel'
    ADDBILLPLAN_URI = '/api/json/nfabilling/addBillPlan'
    MODIFYBILLPLAN_URI = '/api/json/nfabilling/modifyBillPlan'
    MODIFYIPGROUP_URI = '/api/json/nfaipgroup/modifyIPGroup'
    DELETEIPGROUP_URI = '/api/json/nfaipgroup/deleteIPGroup'
    DELETEBILLPLAN_URI = '/api/json/nfabilling/deleteBillPlan'
    CONVERSATION_URI = '/api/json/nfadevice/getConvData'
    TRAFFICDATA_URI = '/api/json/nfadevice/getTrafficData'
    LOGIN_URI = '/apiclient/ember/Login.jsp'
    LOGOUT_URI = '/apiclient/ember/Logout.jsp'

    #HTTP headers data
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

    def _get(self, uri, payload={}):
        '''Method used for GET functions of API.
        Payload must be passed in as dictionary, not kwargs.
        '''

        #Validate session is logged in
        if not self.logged_in:
            raise Exception('Session is not logged in.')

        url = '{0:s}://{1:s}{2:s}'.format(
            self.protocol,
            self.hostname,
            uri,
        )

        #Add API Key to payload
        payload['apiKey'] = self.api_key

        response = self.request.get(url, params = payload)
        
        #Check for 5000 errors/invalid API key
        #If response is string, can't JSON serialize
        try:
            if isinstance(response.json(), dict):
                if response.json().get('error'):
                    raise Exception('{0}: {1}'.format(
                        response.json()['error']['code'],
                        response.json()['error']['message']
                        )
                    )
        except:
            pass

        return response

    def _post(self, uri, payload={}):
        '''Method used for POST functions of API.'''

        #Validate session is logged in
        if not self.logged_in:
            raise Exception('Session is not logged in')
        
        url = '{0:s}://{1:s}{2:s}'.format(
            self.protocol,
            self.hostname,
            uri
        )

        #Add API key to kwargs dict
        payload['apiKey'] = self.api_key

        response = self.request.post(url, data=payload)
        return response

    def _check_required_args(self, arglist, **kwargs):
        '''Validated all required arguments for method exist.'''

        for arg in arglist:
            if not kwargs.get(arg):
                print('Missing required argument: {0}'.format(arg))
                return False
            return True

    def login(self):

        '''Create requests session object, modify its cookie/header
        content, log in to API and retrieve NFA_SSO token
        to be used for all functions
        '''

        if self.logged_in:
            print('User is already logged in')
        else:
           
            #Create authentication payload
            auth_payload = {
                'AUTHRULE_NAME': 'Authenticator',
                'clienttype': 'html',
                'ScreenWidth': '1920',
                'ScreenHeight': '1080',
                'loginFromCookieData': 'false',
                'ntlmv2': 'false',
                'j_username': self.user,
                'j_password': self.password,
                'signInAutomatically': 'on',
                'uname': ''
            }
            
            #Ecryption key payload
            encryption_payload = {
                'requestType': 'AJAX',
                'EncryptPassword': self.password,
                'sid': random.random()
            }
            
            #Load home page for cookie/referrer reasons, grab encrypted key
            home_page = self.request.get('{0:s}://{1:s}'.format(self.protocol, self.hostname))
            j_session_id = home_page.cookies['JSESSIONID']
            encrypt_key = self.request.post(
                '{0:s}://{1:s}/servlets/Settings/Serverlet'.format(self.protocol, self.hostname),
                data = encryption_payload
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
                data=auth_payload
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

    def logout(self):
        
        response = self._get(NFApi.LOGOUT_URI)
        if response.status_code == 200:
            self.logged_in = False

    #=================================================================
    # Administrative methods
    #=================================================================


    def get_ip_groups(self):

        '''
        All IPGroups returned as list of IPGroup objects.

        :rtype: list
        '''
    
        response = self._get(NFApi.LISTIPGROUP_URI).json()
        ip_groups = []

        #Parse JSON output to IPGroup objects
        for ipg in response['IPGroup_List']:
            ip_obj = IPGroup(
                app = ipg['app'],
                dscp = ipg['dscp'],
                name = ipg['base']['Name'],
                description = ipg['base']['desc'],
                speed = ipg['base']['speed'],
                status = ipg['base']['status'],
                ID = ipg['base']['ID'],
                asso_device = ipg['Asso_Device'],
                asso_device_id = ipg['Asso_Dev_id']
            )
            
            #Call method to translate JSON to IP objects
            ip_obj.process_api_group_list(ipg['ip'])
            
            #Finally, add ipgroup object into returned list
            ip_groups.append(ip_obj)
            
        return ip_groups

    def get_bill_plans(self):

        '''
        All billing plans returned as list of BillPlan objects

        :rtype: list
        :returns: list of BillPLan
        '''
        response = self._get(NFApi.LISTBILLPLAN_URI).json()
        bill_plans = []

        #Parse JSON output to BillPlan objects
        for bp in response['bpList']:
            bp_obj = BillPlan(
                name = bp['name'],
                description = bp['desc'],
                cost_unit = bp['coustunit'], #YEA, THEY REALLY HAVE THIS TYPO
                period_type = bp['period'],
                gen_date = bp['billDate'],
                time_zone = bp['tzone'],
                base_speed = bp['basespd1'], #1 returns int instead of str
                base_cost = bp['basecost1'], #1 returns int instead of str
                add_speed = bp['addspd1'],
                add_cost = bp['addcost1'],
                type = bp['type'],
                percent = bp['perc'],
                buss_id = bp['bussList'],
                email_id = bp['emailid'],
                email_sub = bp['emailSubject'],
                plan_id = bp['planid']
            )
            bill_plans.append(bp_obj)

        return bill_plans

    def get_dev_list(self):
        '''
        List all devices/IP Groups and their unique IDs. Needed for adding
        bill plans and IP groups. Returns a list of Device objects.

        :returns: list of Device
        :rtype: list 
        '''

        resp = self._get(NFApi.LISTDEVLIST_URI).json()
        devices = []
        for dev in resp:
            new_dev = Device(name=dev['rName'], IP = dev['rIP'], interfaces = dev['interface'])
            devices.append(new_dev)

        return devices

    def add_ip_group(self, ipgroup):
        '''
        Function to add IPGroup. Function should be passed an IPGroup object type.
        https://www.manageengine.com/products/netflow/help/admin-operations/ip-group-mgmt.html 
        
        :param ipgroup: object of IP Group
        :type ipgroup: manageengineapi.IPGroup
        :returns: json
        :rtype: json
        '''

        if not isinstance(ipgroup, IPGroup):
            raise TypeError('add_ip_group method did not receive IPGroup object')

        #Create payload for URL encoding
        ipg_payload = {
            'GroupName': ipgroup.name,
            'Desc': ipgroup.description,
            'speed': ipgroup.speed,
            'DevList': ipgroup.asso_dev_id,
            'status': ','.join([s.status for s in ipgroup.ip]),
            'IPData': '-'.join([i.api_format for i in ipgroup.ip]),
            'IPType': ','.join([t.type.lower() for t in ipgroup.ip]),
            'ToIPType': ipgroup.to_ip_type,
            'apiKey': self.api_key 
        }
        
        response = self._post(NFApi.ADDIPGROUP_URI, ipg_payload)
        return response.json()
    

    def add_bill_plan(self, billplan):

        '''
        Function to add Bill Plan. 

        :param billplan: Object of bill plan
        :type billplan: manageengineapi.BillPlan
        :returns: json
        '''

        if not isinstance(billplan, BillPlan):
            raise TypeError('add_billing method did not received BillPlan object')
        
        #Construct bill plan payload
        bp_payload = {
            'name': billplan.name,
            'desc': billplan.description,
            'costUnit': billplan.cost_unit,
            'periodType': billplan.period_type,
            'genDate': billplan.gen_date,
            'timezone': billplan.time_zone,
            'apiKey': self.api_key,
            'baseSpeed': billplan.base_speed,
            'baseCost': billplan.base_cost,
            'addSpeed': billplan.add_speed,
            'addCost': billplan.add_cost,
            'type': billplan.type,
            'perc': billplan.percent,
            'intfID': billplan.intf_id,
            'ipgID': billplan.ipg_id,
            'bussID': billplan.buss_id,
            'emailID': billplan.email_id,
            'emailsub': billplan.email_sub
        }

        response = self._post(NFApi.ADDBILLPLAN_URI, bp_payload)
        return response.json()

    def modify_bill_plan(self, billplan):

        '''Function to modify billing object. Looks like it takes same paramters as
        add_billing, but must also include a unique identifier 'plan id'.
        
        :param billplan: existing billing object
        :type billplan: manageengineapi.BillPlan
        :returns: json
        '''
        
        if not isinstance(billplan, BillPlan):
            raise TypeError('modify_billing method did not receive BillPlan object')

        bp_payload = {
            'name': billplan.name,
            'desc': billplan.description,
            'apiKey': self.api_key,
            'baseSpeed': billplan.base_speed,
            'baseCost': billplan.base_cost,
            'addSpeed': billplan.add_speed,
            'addCost': billplan.add_cost,
            'type': billplan.type,
            'perc': billplan.percent,
            'intfID': billplan.intf_id,
            'ipgID': billplan.ipg_id,
            'bussID': billplan.buss_id,
            'emailID': billplan.email_id,
            'emailsub': billplan.email_sub,
            'planid': billplan.plan_id
        }

        response = self._post(NFApi.MODIFYBILLPLAN_URI, bp_payload)
        return response.json()

    def modify_ip_group(self, ipgroup):

        '''Function to modify IPGroup object. Doesn't appear to have any unique parameters, should be able to
        query for IPGroup object with get_ip_groups, modify what we need to modify, then pass to this function 
        to udpate the existing object.

        :param ipgroup: existing ip group
        :type ipgroup: manageengineapi.IPGroup
        :returns: json
        '''
        
        if not isinstance(ipgroup, IPGroup):
            raise TypeError('add_ip_group method did not receive IPGroup object')
        
        #Create payload for URL encoding
        ipg_payload = {
            'GroupName': ipgroup.name,
            'Desc': ipgroup.description,
            'speed': ipgroup.speed,
            'DevList': ipgroup.asso_dev_id,
            'status': ','.join([s.status for s in ipgroup.ip]),
            'IPData': '-'.join([i.api_format for i in ipgroup.ip]),
            'IPType': ','.join([t.type.lower() for t in ipgroup.ip]),
            'ToIPType': ipgroup.to_ip_type,
            'apiKey': self.api_key 
        }
        
        response = self._post(NFApi.MODIFYIPGROUP_URI, ipg_payload)
        return response.json()  

    def delete_ip_group(self, ipg_obj):

        '''Function to delete an IPGroup object. The only required parameter for this is GroupName.

        :param ipg_obj: existing ip group
        :type ipg_obj: manageengineapi.IPGroup
        :returns: json        
        '''

        if not isinstance(ipg_obj, IPGroup):
            raise TypeError('add_ip_group method did not receive IPGroup object')
            
        payload = {
            'apiKey': self.api_key,
            'GroupName': ipg_obj.name
        }
        
        response = self._post(NFApi.DELETEIPGROUP_URI, payload)
        
        #This returns a string, not JSON
        return response.text

    def delete_bill_plan(self, bp):

        '''
        Function to delete billing plan object. Must be passed a BillPlan object.
        
        :param bp: existing bill plan
        :type bp: manageengineapi.BillPlan
        :returns: json
        '''
        
        payload = {
            'apiKey': self.api_key,
            'planID': bp.plan_id
        }
        
        response = self._post(NFApi.DELETEBILLPLAN_URI, payload)
        return response.json()


    #=================================================================
    # Statistic/data methods
    #=================================================================
    

    def get_group_conversation_data(self, ipgroup, payload={}):

        ''' Get conversation data for a specific IP group. IP group should be ID based, not
        named based. Using default params for now, will expand to include more later.
 
        :param ipgroup: ID number of IPGroup
        :type ipgroup: str
        :returns: json 
        '''
    
        if not bool(payload):

            #Query string is empty, default payload
            payload = {
                'apiKey': self.api_key,
                'DeviceID': ipgroup,
                'Count': '10',
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
            print('Did not receive query paramters, using default: {0:s}'.format(str(payload)))

        response = self._get(NFApi.CONVERSATION_URI, payload)
        return response.json()

    def get_group_traffic_data(self, ipgroup, payload={}):

        ''' Get traffic data for specific IP group. 

        :param ipgroup: ID number of IPGroup
        :type ipgroup: str
        :returns: json
        '''

        if not bool(payload):

            #Query string is empty, default payload
            payload = {
                'apiKey': self.api_key,
                'DeviceID': ipgroup,
                'expand': 'false',
                'IPGroup': 'true',
                'TimeFrame': 'today',
                'expand': 'false',
                'tablegripviewtype': 'Chart',
                'Type': 'speed',
                'granularity': 1,
            }
            print('Did not receive query paramters, using default: {0:s}'.format(str(payload)))
        
        response = self._get(NFApi.TRAFFICDATA_URI, payload)
        return response.json()
