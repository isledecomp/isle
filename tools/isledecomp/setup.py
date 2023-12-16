from setuptools import setup, find_packages

setup(
    name="isledecomp",
    version="0.1.0",
    description="Python tools for the isledecomp project",
    packages=find_packages(),
    tests_require=["pytest"],
    include_package_data=True,
    package_data={"isledecomp.lib": ["*.exe", "*.dll"]},
)
