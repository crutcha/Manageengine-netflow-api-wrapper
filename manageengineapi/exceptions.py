class NFApiError(Exception):
    '''Generic exception for NFApi session handler.'''
    
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
