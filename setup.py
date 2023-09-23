from setuptools import setup

setup(name='age_plugin_fido2_hmac',
      version='0.1.0',
      description='A plugin',
      url='https://github.com/olastor/age-plugin-fido2-hmac',
      author='olastor',
      author_email='flyingcircus@example.com',
      license='MIT',
      packages=['age_plugin_fido2_hmac'],
      scripts=['age-plugin-fido2-hmac=age_plugin_fido2_hmac.cli:main'],
      zip_safe=False)
