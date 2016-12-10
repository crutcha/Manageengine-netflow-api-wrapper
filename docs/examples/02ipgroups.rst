IP Groups
=========

IP Groups within ManageEngine are used to keep track specific hosts, networks, or ranges for reporting
and billing purposes. It is either volumetric or speed based, and can be bound to interfaces/devices.
Each IP Group contains a list of IPNetwork or IPRange objects that define what is being tracked. 

For documentation on IPGroup object see: :ref:`ipgroup-object`.

Querying All IP Groups
----------------------

After establishing a session, simply call the 'get' method for IP Groups and you'll received a list of
IPGroup objects. 

.. code-block:: python

    >>> session.get_ip_groups()
    [<IPGroup - Name:Mail Sites ID:2500001>, <IPGroup - Name:Social Network Sites ID:2500002>, <IPGroup - Name:Sports Sites ID:2500004>, <IPGroup - Name:Test IP Group ID:2500034>, <IPGroup - Name:Video Sites ID:2500003>]


Create IP Group for Google DNS
------------------------------

.. code-block:: python

    #Create IPNetwork objects for each DNS server. IPs must be unicode
    #and in CIDR format unless it's a single IP. Unicode is done 
    #for python2/3 compatbility. 
    DNS1 = manageengineapi.IPNetwork(u'8.8.8.8')
    DNS2 = manageengineapi.IPNetwork(u'8.8.4.4/32')

    #Create IPGroup object
    IPG = manageengineapi.IPGroup(
        app = 'All',
        dscp = 'All',
        name = 'Test IP Group',
        description = 'IP Group for Documentation',
        speed = 5000000
    )

    #Add IPs into IP list tracked by IP Group
    IPG.add_ip(DNS1)
    IPG.add_ip(DNS2)

    #Add IPGroup call
    session.add_ip_group(IPG)

JSON will be returned showing status of API call

.. code-block:: python

    >>> session.add_ip_group(IPG)
    {'message': 'IPGroup added successfully', 'GName': 'Test IP Group'}

Modify IP Group
---------------

Now let's say we want to modify our new IP Group. For example, if we want to add another IP...

.. code-block:: python

    #You can use the existing object from earlier, or query all IP Groups
    #and grab the one you want to modify
    for ipg in session.get_ip_groups():
        if ipg.name == 'Test IP Group':
            IPG = ipg

    #Add our new IP
    IPG.add_ip(IPNetwork(u'20.20.20.20'))
    
    #POST to modify API endpoint
    session.modify_ip_group(IPG)

JSON returned with status:

.. code-block:: python

    >>> session.modify_ip_group(IPG)
    {'message': '[Test IP Group] IP Group has been modified successfully'}

Delete IP Group
---------------

To delete an IP Group simply pass an IPGroup object along to the delete method.

.. code-block:: python

    >>> session.delete_ip_group(IPG)
    '[Test IP Group] Deleted Successfully\n'


