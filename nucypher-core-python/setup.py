from setuptools import setup
from setuptools_rust import Binding, RustExtension

from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="nucypher_core",
    description="Protocol structures of Nucypher network",
    long_description=long_description,
    long_description_content_type="text/markdown",
    version="0.8.0",
    author="Bogdan Opanchuk",
    author_email="bogdan@opanchuk.net",
    url="https://github.com/nucypher/nucypher-core/tree/main/nucypher-core-python",
    rust_extensions=[RustExtension("nucypher_core._nucypher_core", binding=Binding.PyO3, debug=False)],
    packages=["nucypher_core"],
    package_data = {
        'nucypher_core': ['py.typed', '__init__.pyi', 'umbral.pyi'],
    },
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Natural Language :: English",
        "Programming Language :: Rust",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
    ],
)
