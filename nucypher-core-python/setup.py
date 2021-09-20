from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name="nucypher_core",
    description="Implementation of Umbral proxy reencryption algorithm",
    version="0.0.1",
    author="Bogdan Opanchuk",
    author_email="bogdan@opanchuk.net",
    url="https://github.com/nucypher/nucypher-core/tree/master/nucypher-core-python",
    rust_extensions=[RustExtension("nucypher_core._nucypher_core", binding=Binding.PyO3)],
    packages=["nucypher_core"],
    #package_data = {
    #    'nucypher_core': ['py.typed', '__init__.pyi'],
    #},
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Rust",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security :: Cryptography",
    ],
)
