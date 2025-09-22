"""
GAuth: AI Power-of-Attorney Authorization Framework - Python Implementation

GAuth enables AI systems to act on behalf of humans or organizations, with explicit,
verifiable, and auditable power-of-attorney flows. Built on OAuth, OpenID Connect,
and MCP, GAuth is designed for open source, extensibility, and compliance with
RFC 111 and RFC 115.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="gauth-py",
    version="0.1.0",
    author="Mauricio Fernandez",
    author_email="mauricio.fernandez@siemens.com",
    description="AI Power-of-Attorney Authorization Framework - Python Implementation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mauriciomferz/Gauth_py",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "gauth-demo=gauth.demo.main:main",
        ],
    },
)