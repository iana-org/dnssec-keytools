import re

from setuptools import setup

with open('src/kskm/version.py', 'r') as fd:
    __version__ = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fd.read(), re.MULTILINE).group(1)


install_requires = [
    "cffi==1.13.2",
    "click==7.0",
    "colorama==0.4.3",
    "cryptography==2.8",
    "itsdangerous==1.1.0",
    "Jinja2==2.11.1",
    "lxml==4.5.0",
    "MarkupSafe==1.1.1",
    "mccabe==0.6.1",
    "mypy-extensions==0.4.3",
    "pycodestyle==2.5.0",
    "pycparser==2.19",
    "pydocstyle==5.0.2",
    "pyflakes==2.1.1",
    "PyKCS11==1.5.7",
    "PyYAML==5.3",
    "six==1.14.0",
    "snowballstemmer==2.0.0",
    "typed-ast==1.4.1",
    "typing-extensions==3.7.4.1",
    "unidecode==1.1.1",
    "voluptuous==0.11.7",
]

testing_extras = [
    "black",
    "coverage",
    "dnspython==1.16.0",
    "eradicate",
    "flask==1.1.1",
    "isort",
    "mypy",
    "nose",
    "nosexcover",
    "parsable",
    "pycryptodome==3.9.4",
    "pylama",
    "pylint",
    "pyopenssl==19.1.0",
    "pytest",
    "wheel",
]

online_extras = ["flask==1.1.1", "pyopenssl==19.1.0", "Werkzeug==0.16.1"]

setup(
    name="kskm",
    version=__version__,
    description=f"KSK Management tools",
    classifiers=["Programming Language :: Python :: 3",],
    keywords="",
    packages=[
        "kskm.common",
        "kskm.keymaster",
        "kskm.ksr",
        "kskm.misc",
        "kskm.signer",
        "kskm.skr",
        "kskm.ta",
        "kskm.tools",
        "kskm.wksr",
    ],
    package_dir={"": "src"},
    namespace_packages=["kskm"],
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    extras_require={"testing": testing_extras, "online": online_extras,},
    entry_points={
        "console_scripts": [
            "kskm-keymaster = kskm.tools.keymaster:main",
            "kskm-ksrsigner = kskm.tools.ksrsigner:main",
            "kskm-sha2wordlist = kskm.tools.sha2wordlist:main",
            "kskm-trustanchor = kskm.tools.trustanchor:main",
            "kskm-wksr = kskm.tools.wksr:main",
        ]
    },
)
