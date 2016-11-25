'''
Object to represent and facilitate  IP Group operations in ManageEngine. All get, add, 
modify, and delete methods of API session relating to IP Group will return objects defined 
here instead of JSON.
'''

from ipaddress import ip_network, IPv4Address, AddressValueError
import re

class IPGroup(object):
    '''
    IP Group object. Group can either be defined by include/exclude of IPNetwork and IPRange 
    objects or defined as between IPNetwork objects. It can not contain both.
    If group definition is for traffic between 2 IP addresses, the IP group can be only for
    those 2 IPs of type between and NOTHING else. 

    More info:
    https://www.manageengine.com/products/netflow/help/admin-operations/ip-group-mgmt.html 
    
    :params app: Applications
    :param dscp: QoS DSCP tags
    :param name: group name
    :param description: group description
    :param speed: speed in bits per second
    :param ID: unique identifier
    :param status: group type. include/exclude for IPs/networks, between for traffic between IPs
    '''

    def __init__(self, **kwargs):
        self.app = kwargs.get('app', 'All')
        self.dscp = kwargs.get('dscp', 'All')
        self.name = kwargs.get('name')
        self.description = kwargs.get('description')
        self.speed = kwargs.get('speed')
        self.ID = kwargs.get('ID')
        self.to_ip_type = None
        self.status = kwargs.get('status', 'Enabled')

        #List of devices coupled with ifIndex
        self.asso_device = kwargs.get('asso_device', 'All Interfaces')
        
        #List of all device identifiers
        self.asso_dev_id = kwargs.get('asso_dev_id', -1)

        #List containing all IPNetwork or IPRange objects applied to IPgroup
        self.ip = kwargs.get('ip', [])

        #Track state of between relationships
        self.is_between = kwargs.get('is_between', False)

    def __repr__(self):
        return '<IPGroup - Name:{0} ID:{1}>'.format(
            self.name,
            self.ID
        )

    def add_ip(self, obj):

        #Check for type of IPBetween.
        if obj.status == 'between':
            
            #If status is 'between' and no between definition exists yet and has valid definition of
            #2 objects, add it. If one exists already, throw an error to caller.
            if self.is_between and len(self.ip) == 2:
                raise ValueError('IPGroup already contains between clause')
            else:
                self.is_between = True
                self.to_ip_type = obj.type.lower()
                self.ip.append(obj)
        
        #Otherwise append other types to ip list
        else:
            self.ip.append(obj)
    
    def process_api_group_list(self, ipgs):
        '''
        Function to parse list of IP definitions from API JSON output
        and return list of IPNetwork/IPRange objects and whether it's
        a between relationships or not. 

        returns ([], bool) 
        '''
        
        for ipdata in ipgs:

            #Between relationships need to be parsed differently. If a between
            #relationship exists, parse and immediately return since only a single
            #between relationship can exist. These are formatted as:
            #[type, 'Between', type, ipinfo, ipinfo, ipinfo]
            if 'between' in [t.lower() for t in ipdata]:
                
                #Process all possible A endpoint types in if/else block
                if ipdata[0].lower() == 'ipaddress':
                    self.add_ip(IPNetwork(cidr=ipdata[3], status='between')) 
                elif ipdata[0].lower() == 'ipnetwork':
                    self.add_ip(IPNetwork(
                            cidr = '/'.join([ipdata[3], ipdata[4]]),
                            status = 'between'
                    ))
                elif ipdata[0].lower() == 'iprange':
                    self.add_ip(IPRange(
                        rangestart = ipdata[3].split()[0],
                        rangeend = ipdata[3].split()[2],
                        netmask = ipdata[4],
                        status = 'between'
                    ))

                #Process all possible B endpoint types in if/else block. These should
                #be sliced in reverse since it is unknown the length of the list being
                #passed to us
                if ipdata[2].lower() == 'ipaddress':
                    self.add_ip(IPNetwork(cidr=ipdata[-1], status='between')) 
                elif ipdata[2].lower() == 'ipnetwork':
                    self.add_ip(IPNetwork(
                            cidr = '/'.join([ipdata[-2], ipdata[-1]]),
                            status = 'include'
                    ))
                elif ipdata[2].lower() == 'iprange':
                    self.add_ip(IPRange(
                        rangestart = ipdata[-2].split()[0],
                        rangeend = ipdata[-2].split()[2],
                        netmask = ipdata[-1]
                    ))

            else:
                #IPRange output isn't returned in a friendly delimited format.
                #Need to normalize data with splits.
                #[
                #  "IPRange",
                #  "Include",
                #  "1.1.1.1 to 1.1.1.8",
                #  "255.255.255.0"
                #]
                if ipdata[0].lower() == 'iprange':
                    self.add_ip(IPRange(
                        rangestart = ipdata[2].split()[0],
                        rangeend = ipdata[2].split()[2],
                        netmask = ipdata[3],
                        status = ipdata[1]
                    ))

                elif ipdata[0].lower() == 'ipaddress':
                    self.add_ip(IPNetwork(cidr=ipdata[2], status=ipdata[1]))
                
                #IPNetwork output isn't friendly either, we prefer data in CIDR
                #format and it gives us network and mask. Need to convert to
                #normalize data between all methods.
                elif ipdata[0].lower() == 'ipnetwork':
                    self.add_ip(IPNetwork(
                        cidr = '/'.join([ipdata[2], ipdata[3]]),
                        status = ipdata[1]
                    ))
 

class IPNetwork(object):
    '''
    Object for both network and host objects. Hosts should be passed in with /32
    subnet mask, or else they will be created as network object with appropriate
    CIDR mask.

    :param cidr: network or host in CIDR format
    :param status: enabled/disabled
    '''

    def __init__(self, cidr=None, status='include'):
        
        #Validate CIDR value passed is valid
        try:
            self.cidr = ip_network(cidr)
        except ValueError:
            raise ValueError('Invalid CIDR address passed to IPNetwork constructor')

        #Set boolean for host or network
        if self.cidr.exploded.split('/') == '32':
            self.is_host = True
            self.type = 'IPAddress'
        else:
            self.is_host = False
            self.type = 'IPNetwork'

        self.status = status
        self.network = self.cidr.with_netmask.split('/')[0]
        self.netmask = self.cidr.with_netmask.split('/')[1]
        self.api_format = ','.join([self.network, self.netmask])
       
    def __repr__(self):
        return '<IPNetwork - Network: {0} Netmask: {1}>'.format(
            self.network,
            self.netmask
        )        
 
class IPRange(object):
    '''
    Object for IP range. Constructor must be passed 2 valid IP addresses that are
    hyphen seperated. Addresses will be stored as IPv4Address objects.

    :param rangestart: IP at beginning of range
    :param rangeend: IP at end of range
    :param netmask: subnet mask of IPs within range
    :param status: enabled/disabled
    '''

    def __init__(self, **kwargs):
        try:
            self.start = IPv4Address(kwargs.get('rangestart'))
            self.end = IPv4Address(kwargs.get('rangeend'))
        except AddressValueError:
            raise ValueError('Invalid start/end address passed to IPRange constructor') 

        self.status = kwargs.get('status')
        self.type = 'IPRange'
        self.netmask = kwargs.get('netmask')
        self.api_format = ','.join(
            [
                self.start.exploded.split('/')[0], 
                self.end.exploded.split('/')[0], 
                self.netmask
            ]
        )

    def __repr__(self):
        return '<IPRange - Start:{0} End:{1}>'.format(
            self.start,
            self.end
        )

class IPBetween:
    '''
    Object to represent between relationship in IP group. Between relationships can happen 
    with any IP type. IE: ipaddress to ipnetwork, ipnetwork to iprange. 

    :param aendpoint: IPRange/IPNetwork object of A endpoint
    :param bendpoint: IPRange/IPNetwork object of B endpoint 
    '''

    def __init__(self, aendpoint, bendpoint):

        #Type checks
        if not isinstance(aendpoint, (IPNetwork, IPRange)):
            raise TypeError('A Endpoint was not a avalid IPNetwork or IPRange object')
        if not isinstance(bendpoint, (IPNetwork, IPRange)):
            raise TypeError('A Endpoint was not a avalid IPNetwork or IPRange object')

        self.aendpoint = aendpoint
        self.bendpoint = bendpoint

