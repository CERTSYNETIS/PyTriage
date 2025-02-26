import os
from setuptools import setup

script_folder = os.path.dirname(os.path.realpath(__file__))


def generate_entry_points():
    """Walk through plugins folder to generate entry points
    Returns:
        entry points dictionary
    """
    entry_points = {"triage_plugins": [], "console_scripts": []}
    entry_points["console_scripts"].append(f"pytriage = triage:main")

    plugins_folder = os.path.join(script_folder, "src", "plugins")
    for plugin_file in os.listdir(plugins_folder):
        if not plugin_file.endswith(".py") or plugin_file == "__init__.py":
            continue
        plugin_name = plugin_file[:-3]
        entry_points["triage_plugins"].append(
            f"{plugin_name} = src.plugins.{plugin_name}:Plugin"
        )
    return entry_points


setup(
    name="pytriage",
    version="1.0.0",
    description="A modern Python-3-based triage service",
    long_description="""SYNETIS Triage service
    """,
    long_description_content_type="text/markdown",
    author="SYNETIS CERT",
    author_email="cert@synetis.com",
    url="",
    python_requires=">=3.9",
    packages=["src", "src.plugins", "src.thirdparty"],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "License :: SYNETIS",
        "Topic :: Utilities",
        "Intended Audience :: Information Technology",
    ],
    scripts=["triage.py"],
    install_requires=[
        "altair==4.2.2",
        "async-timeout==4.0.2",
        "attrs==23.1.0",
        "beautifulsoup4==4.12.2",
        "black==23.3.0",
        "bs4==0.0.1",
        "cachetools==5.3.0",
        "certifi==2022.12.7",
        "cffi==1.15.1",
        "chardet==5.1.0",
        "charset-normalizer==3.1.0",
        "click==8.1.3",
        "cryptography==40.0.2",
        "entrypoints==0.4",
        "enum-compat==0.0.3",
        "frozenlist==1.3.3",
        "google-auth==2.17.3",
        "google-auth-oauthlib==1.0.0",
        "idna==3.4",
        "inotify==0.2.10",
        "Jinja2==3.1.2",
        "jsonschema==4.17.3",
        "markdown-it-py==3.0.0",
        "MarkupSafe==2.1.2",
        "mdurl==0.1.2",
        "multidict==6.0.4",
        "mypy-extensions==1.0.0",
        "networkx==3.1",
        "nose==1.3.7",
        "#ntfsfind==2.5.0",
        "numpy==1.24.3",
        "oauthlib==3.2.2",
        "packaging==23.1",
        "pandas==2.0.1",
        "pathspec==0.11.1",
        "pip-search==0.0.12",
        "platformdirs==3.5.0",
        "psutil==5.9.5",
        "pyasn1==0.5.0",
        "pyasn1-modules==0.3.0",
        "pycparser==2.21",
        "Pygments==2.15.1",
        "pyrsistent==0.19.3",
        "python-dateutil==2.8.2",
        "python-magic==0.4.27",
        "python-registry==1.3.1",
        "pytz==2023.3",
        "PyYAML==6.0",
        "regrippy==2.0.0",
        "requests==2.29.0",
        "requests-oauthlib==1.3.1",
        "rich==13.7.1",
        "rsa==4.9",
        "six==1.16.0",
        "soupsieve==2.4.1",
        "#version 20230721 only uses python version 3.9",
        "timesketch-api-client==20240215",
        "timesketch-import-client==20230721",
        "tomli==2.0.1",
        "toolz==0.12.0",
        "typing-extensions==4.5.0",
        "tzdata==2023.3",
        "unicodecsv==0.14.1",
        "urllib3==1.26.15",
        "websocket-client==1.5.1",
        "xlrd==2.0.1",
        "yarl==1.9.2",
        "zipfile-deflate64==0.2.0",
        "nest-asyncio==1.5.7",
        "python-slugify==8.0.1",
        "flask==3.0.0",
        "flask[async]",
        "elasticsearch==8.16.0",
        "py7zr==0.21.0",
        "aiofiles==23.2.1",
        "aiocsv==1.3.2",
        "pyzipper==0.3.6",
        "lxml==5.3.0",
        "xmltodict==0.14.2",
        "python-evtx==0.7.4",
        "pycryptodome==3.21.0",
        "regipy[full]",
        "libscca-python==20240427",
        "celery==5.4.0",
        "flower==2.0.1",
        "redis==4.3.4",
        "docker==7.1.0",
    ],
    entry_points=generate_entry_points(),
)
