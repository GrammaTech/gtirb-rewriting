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

import logging
import pathlib
import re
import textwrap

import entrypoints
import gtirb
import gtirb_rewriting
import gtirb_rewriting.driver
import gtirb_test_helpers
import mock_entrypoints

TEST_DIR = pathlib.Path(__file__).parent.resolve()

TEST_ENTRYPOINTS = {
    "gtirb_rewriting": [
        entrypoints.EntryPoint(
            "my-pass",
            "test_driver",
            "MyPass",
            distro=entrypoints.Distribution("test_driver", "1.0"),
        ),
        entrypoints.EntryPoint(
            "my-other-pass",
            "test_driver",
            "MyOtherPassDriver",
            distro=entrypoints.Distribution("test_driver", "1.0"),
        ),
    ]
}


class MyPass(gtirb_rewriting.Pass):
    """
    Adds a hardcoded message.
    """

    def end_module(self, module, functions) -> None:
        logging.getLogger("test_driver").debug("debug message")
        module.aux_data["test-data"].data.append("MyPass")


class MyOtherPass(gtirb_rewriting.Pass):
    def __init__(self, message):
        self.message = message

    def end_module(self, module, functions) -> None:
        module.aux_data["test-data"].data.append(self.message)


class MyOtherPassDriver(gtirb_rewriting.driver.PassDriver):
    def add_options(self, group) -> None:
        group.add_argument("--message", required=True)

    def create_pass(self, args, ir):
        return MyOtherPass(args.message)

    def extra_libraries(self, module):
        yield TEST_DIR / "test_driver.py"

    def description(self):
        return "Adds a customizable message."


def write_test_module(tmp_path) -> pathlib.Path:
    ir, m = gtirb_test_helpers.create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    m.aux_data["test-data"] = gtirb.AuxData(
        type_name="sequence<string>", data=[]
    )
    ir_path = tmp_path / "input.gtirb"
    ir.save_protobuf(ir_path)
    return ir_path


def assert_test_module_data(path, expected):
    ir = gtirb.IR.load_protobuf(path)
    assert len(ir.modules) == 1
    assert "test-data" in ir.modules[0].aux_data
    return ir.modules[0].aux_data["test-data"].data == expected


def run_driver(func, *args, **kwargs) -> int:
    with mock_entrypoints.mock_entrypoints(TEST_ENTRYPOINTS):
        try:
            func(*args, **kwargs)
            return 0
        except SystemExit as err:
            return err.code


def test_module_main(tmp_path):
    input_file = write_test_module(tmp_path)
    output_file = tmp_path / "output.gtirb"

    ret = run_driver(
        gtirb_rewriting.driver.main,
        "my-pass",
        argv=["__main__.py", str(input_file), str(output_file)],
    )

    assert ret == 0
    assert_test_module_data(output_file, ["MyPass"])


def test_module_main_with_driver(tmp_path: pathlib.Path):
    input_file = write_test_module(tmp_path)
    output_file = tmp_path / "output.gtirb"
    libs_dir = tmp_path / "libs"
    libs_dir.mkdir()

    ret = run_driver(
        gtirb_rewriting.driver.main,
        "my-other-pass",
        argv=[
            "__main__.py",
            str(input_file),
            str(output_file),
            "--message=hi",
            f"--lib-dir={libs_dir}",
        ],
    )

    assert ret == 0
    assert_test_module_data(output_file, ["hi"])
    assert (libs_dir / "test_driver.py").exists()


def test_module_main_with_class(tmp_path):
    input_file = write_test_module(tmp_path)
    output_file = tmp_path / "output.gtirb"

    ret = run_driver(
        gtirb_rewriting.driver.main,
        MyPass,
        argv=["__main__.py", str(input_file), str(output_file)],
    )

    assert ret == 0
    assert_test_module_data(output_file, ["MyPass"])


def test_module_main_errors(tmp_path):
    ir, m = gtirb_test_helpers.create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    m.aux_data["test-data"] = gtirb.AuxData(
        type_name="sequence<string>", data=[]
    )

    ir.save_protobuf(tmp_path / "input.gtirb")

    # Ensure that the module-specific driver doesn't have --run
    ret = run_driver(
        gtirb_rewriting.driver.main,
        "my-pass",
        argv=[
            "__main__.py",
            "--run=my-pass",
            str(tmp_path / "input.gtirb"),
            str(tmp_path / "output.gtirb"),
        ],
    )
    assert ret == 2

    # Ensure that the module-specific driver doesn't have --list
    ret = run_driver(
        gtirb_rewriting.driver.main, "my-pass", argv=["__main__.py", "--list"],
    )
    assert ret == 2


def test_generic_main(tmp_path):
    input_file = write_test_module(tmp_path)
    output_file = tmp_path / "output.gtirb"

    ret = run_driver(
        gtirb_rewriting.driver.generic_main,
        argv=[
            "gtirb-rewriting",
            "--run=my-other-pass",
            "--run=my-pass",
            str(input_file),
            str(output_file),
            "--message=hi",
        ],
    )

    assert ret == 0
    assert_test_module_data(output_file, ["hi", "MyPass"])


def test_generic_main_version(capsys):
    ret = run_driver(
        gtirb_rewriting.driver.generic_main,
        argv=["gtirb-rewriting", "--version"],
    )

    assert ret == 0

    captured = capsys.readouterr()
    # argparse can wrap our text arbitrarily depending on the host env, so
    # use regexes here.
    assert re.search(
        fr"gtirb_rewriting\s{re.escape(gtirb_rewriting.__version__)}",
        captured.out,
    )
    assert re.search(r"test_driver\s1.0", captured.out)


def test_generic_main_list(capsys):
    ret = run_driver(
        gtirb_rewriting.driver.generic_main,
        argv=["gtirb-rewriting", "--list"],
    )
    assert ret == 0

    captured = capsys.readouterr()
    expected = textwrap.dedent(
        """
        Available passes:
        * my-other-pass
          Adds a customizable message.
        * my-pass
          Adds a hardcoded message.
        """
    ).strip()

    assert captured.out.strip() == expected


def test_generic_main_errors(tmp_path):
    input_file = write_test_module(tmp_path)
    output_file = tmp_path / "output.gtirb"

    # Check that passes can't be listed twice
    ret = run_driver(
        gtirb_rewriting.driver.generic_main,
        argv=[
            "gtirb-rewriting",
            "--run=my-other-pass",
            "--run=my-other-pass",
            str(input_file),
            str(output_file),
            "--message=hi",
        ],
    )

    assert ret == 2
