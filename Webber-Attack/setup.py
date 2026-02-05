from setuptools import setup, find_packages

setup(
    name="webber-attack",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "click",
        "textual",
        "rich",
        "mysql-connector-python",
        "requests",
        "httpx",
        "python-dotenv",
    ],
    entry_points={
        "console_scripts": [
            "webber-attack=src.cli.main:main",
        ],
    },
)