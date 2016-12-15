[![PyPI](https://img.shields.io/pypi/v/manageengineapi.svg)]()

# Manageengine-netflow-api-wrapper
Wrapper for undocumented manageengine netflow API. Only works for v12.

STILL UNDER DEVELOPMENT

TODO:
-----

- [X] Implement modify functions to translate between JSON returned from get methods to data structure
      required for modify methods. (maybe feature as a class)
- [X] Update all docstrings
- [X] Convert all methods to use url encoding instead of string replacement
- [ ] Add all statistic gathering methods
- [ ] Updated existing statistic methods for kwarg parameters
- [ ] Update ipg_id property of billplan to take actual BillPlan objects instead of string, as well as parsing for get method

Installation
------------

This library can be installed using PIP:

    pip install manageengineapi

Alternatively you can install it from cloned respository:

    python setup.py install

Documentation/Getting Started
-----

For examples on how to get started, check out Read the Docs page:

http://manageengine-netflow-api-wrapper.readthedocs.io/en/latest/

