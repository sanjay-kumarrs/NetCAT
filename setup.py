from setuptools import setup, find_packages

setup(
    name="cyber_netcat",
    version="1.0.0",
    description="Cyber_NetCAT - Comprehensive CLI Network Security Assessment Tool",
    author="cyber",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "dnspython>=2.4.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "full": [
            "paramiko>=3.3.0",
            "scapy>=2.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netcat-tool=netcat_tool.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Environment :: Console",
    ],
)
