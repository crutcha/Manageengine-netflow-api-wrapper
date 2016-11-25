from test_settings import nfserver, api_key, username, password
from manageengineapi import NFApi, IPGroup, IPNetwork, IPRange
import unittest

class TestIPGroups(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        self.session = NFApi(nfserver, api_key, username, password)
        self.session.login()
        
        #Create single IP object
        IP = IPNetwork('8.8.8.8')
        
        #Create IPGroup object
        IPG = IPGroup(
            app = 'All',
            dscp = 'All',
            name = 'Unit Testing Group',
            description = 'Unit Testing Description',
            speed = 5000000
        )

        #Add IP to group using add_ip method instead of defining
        #within constructor
        IPG.add_ip(IP)

        #Define IPGroup in object to be used later
        self.ipg = IPG

    @classmethod
    def tearDownClass(self):
        self.session.logout()

    def test01_add_single_ip(self):
        
        #Test app_ip_group call. Function returns JSON, test that the 'message' key matches success
        resp = self.session.add_ip_group(self.ipg)
        print('test_add_single_ip: {0}'.format(resp))
        self.assertEqual(resp['message'], 'IPGroup added successfully')

    def test02_modify_ip_group(self):
        
        #Add second host
        new_ip = IPNetwork('8.8.4.4')
        self.ipg.add_ip(new_ip)

        #API call with modified object
        resp = self.session.modify_ip_group(self.ipg)
        print('test_modify_ip_group: {0}'.format(resp))
        self.assertIn('modified successfully', resp['message'])
    
    def test03_delete_ip_group(self):
        resp = self.session.delete_ip_group(self.ipg)
        print('test_delete_ip_group: {0}'.format(resp))
        self.assertIn('Deleted Successfully', resp)

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIPGroups)
    unittest.TextTestRunner(verbosity=2).run(suite)
