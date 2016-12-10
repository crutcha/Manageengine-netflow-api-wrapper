from test_settings import nfserver, api_key, username, password
from manageengineapi import NFApi, IPGroup, IPNetwork, IPRange, BillPlan
from itertools import chain
import unittest

class TestNFApi(unittest.TestCase):

    @classmethod
    def setUpClass(self):
        print('Setting up testing session...')
        self.session = NFApi(nfserver, api_key, username, password)
        self.session.login()
        
        #List of all unique identifiers known
        all_devs = self.session.get_dev_list()
        self.all_id = list(chain.from_iterable([x.all_idents for x in all_devs]))
        
        #Create single IP object
        IP = IPNetwork(u'8.8.8.8')
        
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

        #New bill plan object
        bp = BillPlan(
            name = 'Unit Test Bill Plan',
            description = 'Unit Test Bill Description',
            cost_unit = 'USD',
            period_type = 'Monthly',
            gen_date = 1,
            time_zone = 'US/Eastern',
            base_speed = 500000,
            base_cost = 50,
            add_speed = 50,
            add_cost = 100,
            type = 'speed',
            percent = 40,
            email_id = 'admin@networkinit.io',
            email_sub = 'Unit Test Email'
        )

        #Attach bill plan to object to use later
        self.bp = bp

    @classmethod
    def tearDownClass(self):
        print('Tearing down testing session....')
        self.session.logout()

    def test01_add_single_ip(self):
        
        #Test app_ip_group call. Function returns JSON, test that the 'message' key matches success
        resp = self.session.add_ip_group(self.ipg)
        print('test_add_single_ip: {0}'.format(resp))
        self.assertEqual(resp['message'], 'IPGroup added successfully')

    def test02_modify_ip_group(self):
        
        #Add second host
        new_ip = IPNetwork(u'8.8.4.4')
        self.ipg.add_ip(new_ip)

        #API call with modified object
        resp = self.session.modify_ip_group(self.ipg)
        print('test_modify_ip_group: {0}'.format(resp))
        self.assertIn('modified successfully', resp['message'])

        #Modify speed
        self.ipg.speed = 8000000

        #API call with modified objects
        resp = self.session.modify_ip_group(self.ipg)
        print('test_modify_ip_group: {0}'.format(resp))
        self.assertIn('modified successfully', resp['message'])
    
    def test03_add_bill_plan(self):
        
        #Test add_bill_plan call
        resp = self.session.add_bill_plan(self.bp)
        print('test_add_plan: {0}'.format(resp))

    def test04_modify_bill_plan(self):

        #Modify API endpoint requires a plan ID which is not returned to us when
        #creating the bill plan. Have to query for all then select which bill
        #plan is ours. 
        bps = self.session.get_bill_plans()
        for bp in bps:
            if bp.name == self.bp.name:
                mod_bp = bp

        #Add all known IP groups to bill plan
        mod_bp.ipg_id = ','.join([str(i.ID) for i in self.session.get_ip_groups()])
        resp = self.session.modify_bill_plan(mod_bp)
        print('modify_bill_plan: {0}'.format(resp))
        self.assertIn('Updated SuccessFully', resp['message']) #Yep, another typo in their code

    def test05_delete_ip_group(self):
        resp = self.session.delete_ip_group(self.ipg)
        print('test_delete_ip_group: {0}'.format(resp))
        self.assertIn('Deleted Successfully', resp)
    
    def test06_delete_bill_plan(self):

        #Grab unit test bill plan
        all_bps = self.session.get_bill_plans()
        for bp in all_bps:
            if bp.name == 'Unit Test Bill Plan':
                test_bp = bp
        
        #Delete unit test plan
        resp = self.session.delete_bill_plan(test_bp)
        print('test_delete_bill_plan: {0}'.format(resp))
        self.assertEquals('Success', resp['message'])

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestNFApi)
    unittest.TextTestRunner(verbosity=2).run(suite)
