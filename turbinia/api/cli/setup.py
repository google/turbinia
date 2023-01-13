"""
Turbinia client command-line tool.

Install via 'pip install turbinia-client'
"""
from setuptools import setup, find_packages
from pathlib import Path

NAME = "turbinia-client"
VERSION = "1.0.1"

REQUIRES = [
    "click",
    "turbinia-api-lib",
]

this_directory = Path(__file__).parent
README = (this_directory / "README.md").read_text()

setup(
    name=NAME, 
    version=VERSION,
    description="Turbinia API Client command-line tool.",
    long_description_content_type="text/markdown",
    long_description=README,
    keywords=[
        "Turbinia Client", "Turbinia", "Turbinia API Server"
    ], 
    python_requires=">=3.6", 
    install_requires=REQUIRES,
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'turbinia-client=turbinia_client.turbiniacli_tool:main'
        ]
    },
    license='Apache License, Version 2.0',
    url='http://turbinia.plumbing/',
    maintainer='Turbinia development team',
    maintainer_email='turbinia-dev@googlegroups.com'
)
