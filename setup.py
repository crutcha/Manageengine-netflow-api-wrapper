from distutils.core import setup
setup(
  name = 'manageengineapi',
  packages = ['manageengineapi'],
  version = '0.1',
  description = 'Wrapper for interacting with ManageEngine Netflow Analyzer v12',
  author = 'Andrew Crutchfield',
  author_email = 'andrewjcrutchfield@gmail.com',
  url = 'https://github.com/crutcha/Manageengine-netflow-api-wrapper', 
  download_url = 'https://github.com/crutcha/Manageengine-netflow-api-wrapper/tarball/0.1',
  install_requires = [
    'requests',
  ],
  extras_require = {
    ':python_version < "2.7"': [
        'ipaddress',
    ],
    },
  classifiers = [],
)
