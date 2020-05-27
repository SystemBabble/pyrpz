import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyrpz-SystemBabble",
    version="0.1alpha1",
    author="Liam Nolan",
    author_email="65938492+SystemBabble@users.noreply.github.com",
    description="A simple tool to generate RPZ Zone files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SystemBabble/pyrpz",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: ISC License (ISCL)",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: System :: Systems Administration"
    ],
    python_requires='>=3.3',
)
