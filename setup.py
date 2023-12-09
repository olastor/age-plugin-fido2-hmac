from setuptools import setup

setup(
    name='age_plugin_fido2_hmac',
    version='0.1.0',
    description='Age plugin for fido2 tokens with hmac extension.',
    url='https://github.com/olastor/age-plugin-fido2-hmac',
    author='olastor',
    author_email='olastor@posteo.org',
    license='MIT',
    packages=['age_plugin_fido2_hmac'],
    install_requires=[
        'cryptography~=41.0',
        'bech32~=1.2',
        'fido2~=1.1'
    ],
    entry_points={
      'console_scripts': ['age-plugin-fido2-hmac=age_plugin_fido2_hmac.cli:main']
    },
    zip_safe=False
)
