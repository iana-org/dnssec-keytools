from setuptools import setup
import subprocess

version = "0.0.1"
git_hash = subprocess.check_output("git rev-parse --short --verify HEAD", shell=True)

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
    "black==19.10b0",
    "coverage==5.0.3",
    "dnspython==1.16.0",
    "eradicate==1.0",
    "flask==1.1.1",
    "mypy==0.761",
    "nose==1.3.7",
    "nosexcover==1.0.11",
    "pycryptodome==3.9.4",
    "pylama==7.6.6",
    "pylint==2.5.3",
    "pyopenssl==19.1.0",
    "pytest==5.4.3",
    "wheel==0.34.2",
]

online_extras = ["flask==1.1.1", "pyopenssl==19.1.0", "Werkzeug==0.16.1"]

setup(
    name="kskm",
    version=version,
    description=f"KSK Management tools ({git_hash})",
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
