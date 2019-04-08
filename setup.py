from setuptools import setup
import subprocess

version = '0.0.1'
git_hash = subprocess.check_output('git rev-parse --verify HEAD', shell=True)

install_requires = [
    'cryptography',
    'PyYAML',
    'PyKCS11'
]

testing_extras = [
    'coverage',
    'dnspython',
    'eradicate',
    'flask',
    'green',
    'mypy',
    'nose==1.3.7',
    'nosexcover',
    'pycryptodome',
    'pylama==7.6.6',
    'pyopenssl',
    'wheel',
]

online_extras = [
    'flask',
    'pyopenssl'
]

setup(
    name='kskm',
    version=version,
    description=f'KSK Management tools ({git_hash})',
    classifiers=[
          'Programming Language :: Python',
    ],
    keywords='',
    packages=[
          'kskm.common',
          'kskm.ksr',
          'kskm.misc',
          'kskm.signer',
          'kskm.skr',
          'kskm.ta',
          'kskm.tools',
    ],
    package_dir={'': 'src'},
    namespace_packages=['kskm'],
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    extras_require={
          'testing': testing_extras,
          'online': online_extras,
    },
    entry_points={
        "console_scripts": [
            'kskm-keymaster = kskm.tools.keymaster:main',
            'kskm-ksrsigner = kskm.tools.ksrsigner:main',
            'kskm-sha2wordlist = kskm.tools.sha2wordlist:main',
            'kskm-trustanchor = kskm.tools.trustanchor:main',
            'kskm-wksr = kskm.tools.wksr:main',
        ]
    },
)
