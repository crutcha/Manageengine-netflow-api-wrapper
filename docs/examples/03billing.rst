Bill Plans
==========

Bill plans allow for usage tracking in either a speed based or volumetric based fashion. They can
track either IP groups or interfaces. For additional information on bill plan features or  properties
of a BillPlan, see the links below. 

:ref:`billplan-object`
https://www.manageengine.com/products/netflow/help/admin-operations/billing.html

Querying All Bill Plans
-----------------------

With an established API session, call the bill plans get method to receive a list of BillPlan objects back.

.. code-block:: python

    >>> session.get_bill_plans()
    [<BillPlan - Name:AWS-IPSec Type:speed, <BillPlan - Name:Google DNS Bill Plan Type:speed]


Create Bill Plan for Google DNS IP Group
----------------------------------------

Using our newly created IPGroup from the previous section,

.. code-block:: python

    #Create BillPlan object using existing IPGroup ID
    bp = manageengineapi.BillPlan(
        name = 'Google DNS Bill Plan',
        description = 'Google DNS Tracking',
        cost_unit = 'USD',
        period_type = 'monthly',
        gen_date = 1,
        time_zone = 'US/eastern',
        base_speed = 5000000,
        base_cost = 100,
        add_speed = 5000000,
        add_cost = 150,
        type = 'speed',
        percent = 41,
        ipg_id = IPG.ID,
        email_id = 'billing@networkinit.io',
        email_sub = 'Google DNS Billing Report'
    )

    #Call to bill plan add endpoint
    session.add_bill_plan(bp)

JSON will be returned showing status of API call

.. code-block:: python

    >>> session.add_bill_plan(bp)
    {'message': 'Success'}


Modify Bill Plan
----------------

To modify a bill plan, make the changes needed to the bill plan object and pass
it along to the modify API endpoint. The modify endpoint requires a plan ID to be
defined, but the add method doesn't supply one to us when it's created, so we'll have to
query bill plans again and pull the one we just created for this example. 

.. code-block:: python

    #Grab our bill plan
    for plan in session.get_bill_plans():
        if plan.name == 'Google DNS Bill Plan':
            bp = plan

    #Adjust plan to be volumetric
    bp.type = 'volume'

    #Adjust base to be 10GB
    bp.base_speed = 10000000000

    #Adjust overage to 1GB chunks
    bp.add_speed = 1000000000

    #Adjust base cost to 0, charge $50 for overage
    bp.base_cost = 0
    bp.add_cost = 50

    #Call to API modify endpoint
    session.modify_bill_plan(bp)

And again, JSON from API passed straight back to us. 

.. code-block:: python

    >>> session.modify_bill_plan(bp)
    {'message': 'Updated SuccessFully'}

Delete IP Group
---------------

To delete a bill plan simply pass a BillPlan object along to the delete method.

.. code-block:: python

    >>> session.delete_bill_plan(bp)
    {'message': 'Success'}



