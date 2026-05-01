from setuptools import setup, find_packages

setup(
    name="gods-eye",
    version="1.0.0",
    description="GOD'S EYE — AI-powered penetration testing and red team automation",
    author="alisalive",
    python_requires=">=3.11",
    packages=find_packages(),
    install_requires=[
        "rich>=13.0.0",
        "typer>=0.9.0",
        "aiohttp>=3.9.0",
        "anthropic>=0.25.0",
        "pydantic>=2.0.0",
        "requests>=2.31.0",
        "dnspython>=2.4.0",
        "playwright>=1.40.0",
        "ldap3>=2.9.0",
        "PyYAML>=6.0.0",
        "packaging>=23.0",
    ],
    entry_points={
        "console_scripts": [
            "godseye=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
