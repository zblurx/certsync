from setuptools import setup

setup(
    name="certsync",
    version="0.1.0",
    author="zblurx",
    author_email="seigneuret.thomas@pm.me",
    description="Dump NTDS with golden certificates and UnPAC the hash",
    long_description="README.md",
    long_description_content_type="text/markdown",
    url="https://github.com/zblurx/certsync",
    license="MIT",
    install_requires=[
        "certipy-ad==4.3.0",
        "tqdm",
    ],
    python_requires='>=3.6',
    packages=[
        "certsync",
],
    entry_points={
        "console_scripts": ["certsync=certsync.entry:main"],
    },
)
