'''
Object to represent and facilitate  IP Group operations in ManageEngine. All get, add, 
modify, and delete methods of API session relating to IP Group will return objects defined 
here instead of JSON.
'''

from ipaddress import ip_network, IPv4Address, AddressValueError
import re

class IPGroup:
    '''
    IP Group object. Group can either be defined by include/exclude of IPNetwork and IPRange 
    objects or defined as between IPNetwork objects. It can not contain both.
    
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
        self.status = kwargs.get('status')
        self.ID = kwargs.get('ID')

        #List of devices coupled with ifIndex
        self.asso_device = kwargs.get('asso_device', 'All Interfaces')
        
        #List of all device identifiers
        self.asso_dev_id = kwargs.get('asso_dev_id')

        #List containing all IPNetwork or IPRange objects applied to IPgroup
        self.ip = []
       
    def __repr__(self):
        return '<IPGroup - Name:{0} ID:{1}>'.format(
            self.name,
            self.ID
        )
 

class IPNetwork:
    '''
    Object for both network and host objects. Hosts should be passed in with /32
    subnet mask, or else they will be created as network object with appropriate
    CIDR mask.

    :param cidr: network or host in CIDR format
    '''

    def __init__(self, cidr=None):
        
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

        self.network = self.cidr.with_netmask.split('/')[0]
        self.netmask = self.cidr.with_netmask.split('/')[1]
       
    def __repr__(self):
        return '<IPNetwork - Network: {0} Netmask: {1}>'.format(
            self.network,
            self.netmask
        )        
 
class IPRange:
    '''
    Object for IP range. Constructor must be passed 2 valid IP addresses that are
    hyphen seperated. Addresses will be stored as IPv4Address objects.

    :param rangestart: IP at beginning of range
    :param rangeend: IP at end of range
    :param netmask: subnet mask of IPs within range
    '''

    def __init__(self, rangestart, rangeend, netmask):
        try:
            self.start = IPv4Address(kwargs.get('rangestart'))
            self.end = IPv4Address(kwargs.get('rangeend'))
        except AddressValueError:
            raise ValueError('Invalid start/end address passed to IPRange constructor') 


        self.type = 'IPRange'
        self.netmask = kwargs.get('netmask')

    def __repr__(self):
        return '<IPRange - Start:{0} End:{1}>'.format(
            self.start,
            self.end
        )

