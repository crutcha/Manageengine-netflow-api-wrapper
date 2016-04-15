# Manageengine-netflow-api-wrapper
Wrapper for undocumented manageengine netflow API. Only works for v12.

WORK IN PROGRESS, NOT FINISHED

To-Do:

* Figure out API authentication(NFA__SSO)
* Validation for objects passed into add/POST methods. API will still report success despite invalid objects being passed to it. (ie: ipgID does not exist/invalid)
* Convert all modify calls to urlencoding. Possibly combine modify functionality? 
