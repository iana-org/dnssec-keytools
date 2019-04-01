from setuptools import setup

version = '0.0.1'

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
    description='KSK Management tools',
    classifiers=[
          'Programming Language :: Python',
    ],
    keywords='',
    packages=[
          'kskm.ksr',
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
            'kskm-keybackup = kskm.tools.keybackup',
            'kskm-kskgen = kskm.tools.kskgen',
            'kskm-ksrsigner = kskm.tools.ksrsigner',
            'kskm-sha2wordlist = kskm.tools.sha2wordlist',
            'kskm-trustanchor = kskm.tools.trustanchor',
            'kskm-wksr = kskm.tools.wksr',
        ]
    },
)
