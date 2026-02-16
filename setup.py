from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ja4plus",
    version="0.2.0",
    description="JA4+ network fingerprinting library for TLS, TCP, HTTP, SSH, and X.509 analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Crank-Git/ja4plus",
    project_urls={
        "Bug Tracker": "https://github.com/Crank-Git/ja4plus/issues",
        "Source Code": "https://github.com/Crank-Git/ja4plus",
        "Documentation": "https://github.com/Crank-Git/ja4plus/tree/main/docs",
        "JA4+ Specification": "https://github.com/FoxIO-LLC/ja4",
    },
    license="BSD-3-Clause",
    packages=find_packages(exclude=["tests", "tests.*", "examples"]),
    install_requires=[
        "scapy>=2.4.0",
        "cryptography>=3.4.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=3.0",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
    ],
    keywords="ja4 ja4plus fingerprinting tls tcp http ssh x509 network security scapy",
)
