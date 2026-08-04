from setuptools import setup, find_packages

setup(
    name="nvctl",
    version="3.0.0",
    description="NanoVault Enterprise CLI",
    packages=find_packages(),
    install_requires=["click>=8.1.7", "httpx>=0.27.0", "rich>=13.7.1"],
    entry_points={"console_scripts": ["nvctl=nvctl.main:cli"]},
    python_requires=">=3.9",
)
