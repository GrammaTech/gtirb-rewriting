# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2021 GrammaTech, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
import imp

import setuptools

version = imp.load_source(
    "pkginfo.version", "gtirb_rewriting/version.py"
).__version__

setuptools.setup(
    name="gtirb-rewriting",
    version=version,
    author="GrammaTech",
    author_email="gtirb@grammatech.com",
    description="Utilities for rewriting GTIRB",
    packages=setuptools.find_packages(),
    install_requires=[
        "gtirb-capstone",
        "gtirb-functions",
        "gtirb",
        "mcasm",
        "dataclasses ; python_version<'3.7.0'",
    ],
    classifiers=["Programming Language :: Python :: 3"],
    extras_require={
        "test": [
            "flake8",
            "isort",
            "pytest",
            "pytest-cov",
            "tox",
            "tox-wheel",
            "pre-commit",
        ]
    },
    url="https://github.com/grammatech/gtirb-rewriting",
    license="GPLv3",
)
