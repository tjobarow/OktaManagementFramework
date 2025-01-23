from setuptools import setup

setup(
    name="OktaManagementFramework",
    version="1.23",
    py_modules=['okta_management_framework'],
    install_requires=[
        "certifi==2024.12.14",
        "charset-normalizer==3.4.0",
        "idna==3.10",
        "requests==2.32.3",
        "urllib3==2.2.3",
    ],
    author="Thomas Obarowski",
    author_email="tjobarow@gmail.com",
    description="A wrapper for several functions of the Okta Management API I frequently find myself using.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)
