# GTIRB-Rewriting Rewriting API for GTIRB
# Copyright (C) 2022 GrammaTech, Inc.
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

import argparse
import logging
import os
import shutil
import sys
import textwrap
from abc import ABC, abstractmethod
from typing import Any, Iterable, List, Mapping, Optional, Tuple, Type, Union

import entrypoints as entrypoints_module
import gtirb
import gtirb_capstone
import gtirb_functions
from typing_extensions import Protocol

from .passes import Pass, PassManager
from .version import __version__


class DriverLoadError(RuntimeError):
    """
    A pass or driver failed to load from an entry point.
    """

    pass


class PassDriver(ABC):
    """
    A driver that provides command line options and creates a rewriting pass.
    """

    def add_options(self, group) -> None:
        """
        Add pass-specific options to an argparse group. Optional.
        :param group: The argparse group object (the result of
                      ArgumentParser.add_argument_group).

        Option names should be unique across passes, so consider names like
        --no-lep-init instead of just --no-init (where lep is part of the pass
        name).
        """
        pass

    @abstractmethod
    def create_pass(self, args: argparse.Namespace, ir: gtirb.IR) -> Pass:
        """
        Creates an instance of the pass to run.
        :param args: The parsed arguments for all pass drivers.
        :param ir: The IR the pass will be ran on.
        """
        pass

    def extra_libraries(
        self, module: gtirb.Module
    ) -> Iterable[Union[str, os.PathLike]]:
        """
        Extra libraries that must be present in the same folder as the binary.
        Optional.
        :param module: The GTIRB Module that might need extra libraries.
        """
        return ()

    def description(self) -> Optional[str]:
        """
        A description of what the pass does. Optional.
        """
        return None


class _EntryPointCompatible(Protocol):
    """
    A protocol compatible with a subset of entrypoint's Entrypoint class.
    """

    @property
    def name(self) -> str:
        ...

    @property
    def distro(self) -> Optional[entrypoints_module.Distribution]:
        ...

    def load(self) -> Any:
        ...


class _PassEntryPointAdaptor:
    """
    An entrypoint-compatible class that exposes a pass or pass driver as an
    entrypoint.
    """

    def __init__(
        self, name: str, pass_or_driver: Type[Union[Pass, PassDriver]]
    ) -> None:
        self.pass_or_driver = pass_or_driver
        self.name = name
        self.distro = None

    def load(self) -> Any:
        return self.pass_or_driver


class _PassDriverAdaptor(PassDriver):
    """
    Exposes a Pass class as a PassDriver.
    """

    def __init__(self, pass_: Pass) -> None:
        self.pass_ = pass_

    def description(self) -> Optional[str]:
        return self.pass_.__doc__

    def create_pass(self, args: argparse.Namespace, ir: gtirb.IR) -> Pass:
        return self.pass_


def _make_version_string(entrypoints: Iterable[_EntryPointCompatible]) -> str:
    """
    Creates a version string for all of the rewriting infrastructure and the
    entrypoints.
    """

    versions: List[str] = []
    versions.append(f"gtirb {gtirb.__version__}")
    versions.append(f"gtirb_capstone {gtirb_capstone.__version__}")
    versions.append(f"gtirb_functions {gtirb_functions.__version__}")
    versions.append(f"gtirb_rewriting {__version__}")
    distros = set(
        (ep.distro.name, ep.distro.version) for ep in entrypoints if ep.distro
    )
    for name, version in sorted(distros):
        versions.append(f"{name} {version}")
    return ", ".join(versions)


class _ListPassesAction(argparse.Action):
    """
    An argparse action that prints the list of available passes and exits.
    """

    def __init__(
        self,
        option_strings,
        entrypoints: List[_EntryPointCompatible],
        dest=argparse.SUPPRESS,
        default=argparse.SUPPRESS,
        help=None,
    ):
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )
        self.entrypoints = entrypoints

    def __call__(self, parser, namespace, values, option_string=None):
        width = shutil.get_terminal_size().columns
        # If we get something way too small, assume the width is 80 and let
        # the terminal emulator deal with wrapping it.
        if width < 10:
            width = 80

        print("Available passes:")
        for ep in sorted(self.entrypoints, key=lambda ep: ep.name):
            print(f"* {ep.name}")
            try:
                driver = _load_entrypoint(ep)
            except DriverLoadError:
                continue

            description = driver.description()
            if description:
                for line in textwrap.wrap(
                    textwrap.dedent(description).strip(),
                    width - 5,
                    initial_indent="  ",
                    subsequent_indent="  ",
                ):
                    print(line)

        parser.exit()


def _driver_core(
    entrypoints: Iterable[_EntryPointCompatible],
    is_generic_driver: bool,
    argv: List[str],
) -> None:
    """
    The implementation of the gtirb-rewriting driver.
    :param entrypoints: The found gtirb_rewriting entry points.
    :param is_generic_driver: Should we be the gtirb-rewriting driver or the
                              pass-specific driver?
    :param argv: The argument vector to parse.
    """

    logging.basicConfig(format="%(message)s")

    description: Optional[str] = None
    if is_generic_driver:
        description = "gtirb-rewriting driver"
        prog = "gtirb-rewriting"

        # We need a first argument parser to determine what passes to load.
        # Then we can have a second argument parser that has all of the
        # options, including the options from the passes.
        passes_ap = argparse.ArgumentParser(
            prog=prog, description=description, add_help=False
        )
        passes_ap.add_argument(
            "--run",
            action="append",
            default=[],
            dest="passes",
            help="pass to run",
            choices=sorted(ep.name for ep in entrypoints),
        )
        passes_args, _ = passes_ap.parse_known_args(argv[1:])

        unique_passes = set(passes_args.passes)
        if len(unique_passes) != len(passes_args.passes):
            passes_ap.error("pass names cannot be repeated")

        entrypoints_by_name = {ep.name: ep for ep in entrypoints}
        loaded_drivers: List[Tuple[_EntryPointCompatible, PassDriver]] = []
        for name in passes_args.passes:
            ep = entrypoints_by_name[name]
            try:
                loaded_drivers.append((ep, _load_entrypoint(ep)))
            except DriverLoadError as err:
                passes_ap.error(str(err))

    else:
        # Because we're being told exactly what to load programatically and
        # not from user input, fail hard if there are load errors.
        loaded_drivers = [(ep, _load_entrypoint(ep)) for ep in entrypoints]

        prog = os.path.basename(argv[0])
        description = loaded_drivers[0][1].description()
        if description:
            description = textwrap.dedent(description).strip()

    ap = argparse.ArgumentParser(prog=prog, description=description)
    ap.add_argument("in_ir", help="input GTIRB IR")
    ap.add_argument("out_ir", help="output GTIRB IR")
    if is_generic_driver:
        ap.add_argument(
            "--run",
            action="append",
            default=[],
            dest="passes",
            help="pass to run",
            choices=sorted(ep.name for ep in entrypoints),
        )
        ap.add_argument(
            "--list",
            entrypoints=entrypoints,
            help="list registered passes and exit",
            action=_ListPassesAction,
        )
    ap.add_argument(
        "--lib-dir", help="output directory for added dependencies"
    )
    ap.add_argument(
        "--version",
        action="version",
        version=_make_version_string(entrypoints),
    )
    ap.add_argument(
        "--debug", action="store_true", help="print debug information"
    )
    for ep, driver in loaded_drivers:
        group = ap.add_argument_group(ep.name)
        driver.add_options(group)

    args = ap.parse_args(argv[1:])

    if args.debug:
        logging.getLogger("gtirb_rewriting").setLevel(logging.DEBUG)
        for ep, _ in loaded_drivers:
            if ep.distro:
                logging.getLogger(ep.distro.name).setLevel(logging.DEBUG)

    ir = gtirb.IR.load_protobuf(args.in_ir)

    pass_man = PassManager()
    for _, driver in loaded_drivers:
        pass_man.add(driver.create_pass(args, ir))
    pass_man.run(ir)

    ir.save_protobuf(args.out_ir)

    if args.lib_dir:
        for module in ir.modules:
            for _, driver in loaded_drivers:
                for lib in driver.extra_libraries(module):
                    shutil.copy(str(lib), args.lib_dir)


def main(
    name_or_class: Union[str, Type[Pass], Type[PassDriver]],
    *,
    argv: List[str] = sys.argv,
) -> None:
    """
    Provides a standard command-line driver for a single rewriting transform.
    :param name_or_class: The entrypoint name (must match setup.py) or the
                          Pass class or PassDriver class.
    :param argv: The argv to use (defaults to sys.argv).
    """

    if isinstance(name_or_class, str):
        entrypoint = entrypoints_module.get_single(
            "gtirb_rewriting", name_or_class
        )
    else:
        # We go out of our way to allow this for simple command line scripts
        # that are not packages (mostly useful in examples).
        entrypoint = _PassEntryPointAdaptor(
            name_or_class.__name__, name_or_class
        )

    _driver_core([entrypoint], False, argv)


def generic_main(
    *,
    argv: List[str] = sys.argv,
    extra: Mapping[str, Union[Type[Pass], Type[PassDriver]]] = {},
) -> None:
    """
    The generic gtirb-rewriting driver, used to implement the gtirb-rewriting
    command line tool.
    :param argv: The argv to use (defaults to sys.argv).
    :param extra: Extra passes or pass drivers to register.
    """
    entrypoints: List[_EntryPointCompatible] = []
    entrypoints.extend(entrypoints_module.get_group_all("gtirb_rewriting"))
    entrypoints.extend(
        _PassEntryPointAdaptor(name, value) for name, value in extra.items()
    )

    _driver_core(entrypoints, True, argv)


def _load_entrypoint(ep: _EntryPointCompatible) -> PassDriver:
    """
    Loads an entrypoint to get a PassDriver or raises DriverLoadError.
    """

    try:
        ep_function = ep.load()
    except Exception as err:
        raise DriverLoadError(f"failed to load {ep.name}: {err}")

    try:
        pass_or_driver = ep_function()
    except Exception as err:
        raise DriverLoadError(f"failed to load driver {ep.name}: {err}")

    # We allow the entrypoint to be either a PassDriver or a Pass. Create an
    # adaptor for the Pass objects to avoid the rest of the code having to
    # care.
    if isinstance(pass_or_driver, PassDriver):
        driver = pass_or_driver
    elif isinstance(pass_or_driver, Pass):
        driver = _PassDriverAdaptor(pass_or_driver)
    else:
        raise DriverLoadError(
            f"failed to instantiate {ep.name}: object was not a Pass or "
            "PassDriver"
        )

    return driver
