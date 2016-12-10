Session Management - Login/Logout
=================================

All calls to API are handled by a session tracked by NFApi object. In
order to initialize a session object, you'll need to provide both credentials
and an API key. Your API key can be found in in the settings pane on the bottom
left of the web UI. Once you are logged in, all cookies needed for future calls
are stashed within the object until you logout. 

Logging In
----------

    import manageengine

    session = manageengineapi.NFApi(
        'your_server_here',
        'your_api_key',
        'apiuser',
        'apipassword'
    )
    session.login()

Logging Out
-----------

    session.logout()
