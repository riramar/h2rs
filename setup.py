import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="h2rs",
    version="0.0.1",
    author="Ricardo Iramar dos Santos",
    author_email="ricardo.iramar@gmail.com",
    description="Detects request smuggling via HTTP/2 downgrades.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/riramar/h2rs/",
    project_urls={
        "Bug Tracker": "https://github.com/riramar/h2rs/issues",
    },
    entry_points={
        "console_scripts": ['h2rs = h2rs.h2rs:main']
        },
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ),
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    install_requires=[
        'certifi',
        'h2',
    ],
)
