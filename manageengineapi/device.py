class Device(object):
    '''
    Device object. Contains all interfaces and unique IDs that apply to a device.

    :param name: Name of device
    :param IP: IP address of device
    :interfaces: list of interfaces. each interface is list containing ID and name.
    :all_idents: contains list of only unique identifiers of interfaces on device
    '''

    def __init__(self, **kwargs):
        self.name = kwargs.get('name')
        self.IP = kwargs.get('IP')
        self.interfaces = kwargs.get('interfaces')

        #Populate all unique idents into list
        self.all_idents = [i[0] for i in self.interfaces]

    def __repr__(self):
        return '<Device - Name:{0} IP:{1}'.format(
            self.name,
            self.IP
        )

