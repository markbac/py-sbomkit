from setuptools import setup, find_packages

setup(
    name="py-sbomkit",
    version="0.2.0",
    description="Universal Software Bill of Materials (SBOM) Generator Toolkit",
    author="Mark Bacon",
    packages=find_packages(),
    install_requires=[
        "colorlog>=6.7.0",
        "PyYAML>=6.0"
    ],
    entry_points={
        "console_scripts": [
            "py-sbomkit=pysbomkit.cli:main",
        ],
    },
    python_requires=">=3.9",
)
