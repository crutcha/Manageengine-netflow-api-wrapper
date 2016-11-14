# Manageengine-netflow-api-wrapper
Wrapper for undocumented manageengine netflow API. Only works for v12.

WORK IN PROGRESS, NOT FINISHED

TODO:
-----

- [ ] Implement modify functions to translate between JSON returned from get methods to data structure
      required for modify methods.
- [ ] Update all docstrings
- [X] Convert all methods to use url encoding instead of string replacement

Installation
------------

This library can be installed using PIP:

    pip install manageengineapi

Alternatively you can install it from cloned respository:

    python setup.py install

Usage
-----

Every object within in the API has 4 methods: get, add, modify, and delete. Every method takes 
object parameters as a dictionary. For example...

Add IP Group to track Google DNS traffic:

    import manageengineapi

    session = manageengineapi.NFApi(
        'your_server_here',
        'your_api_key', #API key found in settings
        'apiuser', #User with administrative privs
        'apipassword', #password
    )

    session.login()

    #Add IP Group
    ip_group_params = {
        'GroupName': 'Google DNS',
        'Desc': 'API test',
        'speed': 50000,
        'DevList': '-1',
        'status': 'include,include',
        'IPData': '8.8.8.8-8.8.4.4',
        'IPType': 'ipaddress,ipaddress',
    }
    
    result = session.add_ip_group(ip_group_params)

JSON returned to us shows group was successfully created.

    >>> result
    {'message': 'IPGroup added successfully', 'GName': 'Google DNS'}


