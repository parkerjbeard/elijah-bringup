from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text() if (this_directory / "README.md").exists() else ""

setup(
    name="elijahctl",
    version="1.0.0",
    author="Elijah Team",
    description="CLI tool for automated drone provisioning and verification",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/elijah/elijahctl",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    install_requires=[
        "click>=8.1.0",
        "requests>=2.31.0",
        "paramiko>=3.3.0",
        "pymavlink>=2.4.41",
        "pyyaml>=6.0.1",
        "rich>=13.5.0",
        "telnetlib3>=2.0.0",
        "python-dotenv>=1.0.0",
        "cryptography>=41.0.0",
        "aiohttp>=3.8.0",
        "pydantic>=2.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.11.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "mypy>=1.5.0",
            "ruff>=0.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "elijahctl=elijahctl.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)