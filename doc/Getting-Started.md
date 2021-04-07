# Getting Started

## Transform Structure

A transform will be typically implemented as a single `Pass` subclass, which
implements `begin_module` and at least one `Patch` subclass (or function
decorated with `@patch_constraints`, if using `Patch.from_function`). Inside
of the `begin_module` callback, the pass will register any modifications with
the passed `RewritingContext`.

## Starting Template

The below example has a simple command line driver, along with a pass that
just adds a `nop` instruction at the entry of all code blocks.

```python
import argparse
import logging

import gtirb
from gtirb_rewriting import *


class NopPass(Pass):
    def begin_module(self, module, functions, context):
        context.register_insert(
            AllBlocksScope(BlockPosition.ENTRY),
            Patch.from_function(self.nop_patch),
        )

    @patch_constraints()
    def nop_patch(self, context):
        return "nop"


def main():
    logging.basicConfig(format="%(message)s")

    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("outfile")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    if args.verbose:
        logging.getLogger("gtirb_rewriting").setLevel(logging.DEBUG)

    ir = gtirb.IR.load_protobuf(args.infile)

    pass_man = PassManager()
    pass_man.add(NopPass())
    pass_man.run(ir)

    ir.save_protobuf(args.outfile)


if __name__ == "__main__":
    main()
```

## Disassembling

Creating a GTIRB IR file is accomplished with the `ddisasm` tool. A typical
invocation will look like:
```bash
ddisasm binary --ir binary.gtirb
```

Additionally, specifying `-j1` may speed up disassembly on some systems as
ddisasm incurs extra overhead running parallel.

## Reassembling

Reassembling the modified GTIRB IR is done with the `gtirb-pprinter` tool. For
Linux, the invocation typically looks like:
``` bash
gtirb-pprinter \
  --keep-all \
  --skip-section .rela.dyn \
  --skip-section .rela.plt \
  --skip-section .eh_frame \
  -c -nostartfiles \
  modified_binary.gtirb \
  -b modified_binary
```

This tells the pretty-printer to keep all sections and symbols, except for
those relating to relocations or exception handling.  This is necessary to
be able to rewrite the code in `_start` (otherwise the pretty-printer will
default to skipping it and letting the compiler regenerate it).

Note that rewriting of binaries that rely on exception handling tables is not
currently supported.


# Common Tasks & Questions

## Inserting a Function Call

gtirb-rewriting provides a `CallPatch` class that is able to insert function
calls using the platform's ABI. Its constructor takes the symbol to call,
along with the arguments to pass. Arguments currently must be either a Symbol,
an integer, or a callable that is passed an InsertionContext and returns
either a Symbol or an integer.

For example, inserting a call to exit with a fixed status code:
```python
# at the top of the file
from gtirb_rewriting.patches import CallPatch

# in a Pass's begin_module callback:
exit_sym = context.get_or_insert_extern_symbol('exit', 'libc.so.6')
context.register_insert(..., CallPatch(exit_sym, [42]))
```

## Inserting Initialization Code

Passes frequently need to insert initialization code that is executed before
any code in the program runs. This is accomplished by using a
`SingleBlockScope` with the module's `entry_point` as the block.

For example, inserting a call to initialize some supporting library:
```python
# at the top of the file
from gtirb_rewriting.patches import CallPatch

# in a Pass's begin_module callback:
init_sym = context.get_or_insert_extern_symbol(
    'init_support_code', 'libsupport.so')
context.register_insert(
    SingleBlockScope(module.entry_point, BlockPosition.ENTRY),
    CallPatch(init_sym))
```

## Disassembling Existing Code

Disassembly is done via `gtirb_capstone`'s `GtirbInstructionDecoder` object,
like so:
```python
# at the top of the file:
from gtirb_capstone.instructions import GtirbInstructionDecoder

# in a Pass's begin_module callback:
decoder = GtirbInstructionDecoder(module.isa)
for function in functions:
    for block in function.get_all_blocks():
        offset = 0
        for instruction in decoder.get_instructions(block):
            pass # do something with the instruction here
            offset += instruction.size
```

## Scratch Registers

Patches can specify how many scratch general-purpose registers they require
by setting `scratch_registers` in their constraints object. gtirb-rewriting
will then pass that many register objects as parameters (after the insertion
context).

Register objects can be formatted into a string to get the register name,
optionally using the format specifier to get the name of a subregister.

Additionally, gtirb-rewriting will implicitly generate code to spill/restore
the scratch registers as needed around the patch.

For example, a patch that takes two scratch registers:
```python
@patch_constraints(scratch_registers=2)
def sample_patch(self, context, reg1, reg2):
    return f"""
    mov $0, %{reg1}
    mov $1, %{reg2:32}
    """
```

Imagining that registers chosen were `rax` and `rbx` on x64-64, this patch
would expand to:
```
mov $0, %rax
mov $1, %ebx
```

## Constraints

A patch's constraints should describe what the patch's assembly will be doing
in terms of what it clobbers. This allows gtirb-rewriting to spill/restore
registers correctly.

Here is a summary of the current constraints:
* `align_stack`: aligns the stack to the ABI required alignment for calling a
  function
* `clobbers_flags`: preserves the flags register
* `clobbers_registers`: preserves specific registers by name
* `preserve_caller_saved_registers`: preserved the registers that are
  considered caller-saved during a function call by the ABI
* `scratch_registers`: see the above section on scratch registers
* `x86_syntax`: choose between using Intel and AT&T assembly syntax for the
  patch

## Labels

Patches are free to refer to existing symbols in the program and to introduce
new labels, though the label names must not conflict with symbols already
present. To assist with this, gtirb-rewriting will automatically suffix
"temporary" labels, e.g. those starting with `.L` for ELF x86-64, with a
unique integer behind the scenes.

For example, the following patch will actually generate symbols like
`.Lmy_label_1`, etc:
```python
def get_asm(self, context):
    return """
        jmp .Lmy_label
        .Lmy_label:
        nop
    """
```

If your patch is intended to be portable across different ABIs, you can use
`ABI.temporary_label_prefix` to get the prefix needed for a temporary label or
`InsertionContext.temporary_label` create an appropriate label. For example:
```python
def get_asm(self, context):
    label = context.temporary_label("my_label")
    return """
        jmp {label}
        {label}:
        nop
    """
```

## Getting a Block's Original Address

For profiling and tracing transforms, it's common to want to know the original
address of a given block of code. While it is possible to access the block's
address from within a patch's get_asm method via the `InsertionContext`, this
will give you the **wrong** answer because the address gets modified in the
process of applying transforms.

Instead, transforms should create a dict from code block to original address
in the Pass's begin_module callback and refer to that later on.

## Replacements

Instructions can be replaced using the `replace_at` function, which takes
the location to modify (function / code block / offset), the number of bytes
to replace, and the patch to replace them with. Both the location and the
number of bytes to replace must fall on instruction boundaries.

## Deletions

gtirb-rewriting does not currently support doing deletions, though it is
planned for the future. A workaround for now is to perform a replacement with
a `nop` instruction as the patch.

Here is a function that performs the workaround:
```python
def delete_at(rewriting_context, func, block, offset, length):
    @patch_constraints()
    def nop_patch(insertion_context):
        return "nop"

    rewriting_context.replace_at(
        func, block, offset, length, Patch.from_function(nop_patch))
```

## `.byte` Directive

Patches can use the `.byte` directive (and similar directives) to either emit
raw data in the patch or instructions that the assembler may not understand.
Instructions added via `.byte` must not have an impact on control flow.

gtirb-rewriting uses a simple heuristic to determine, at the block level,
code from data: if the block has any incoming edges or contains other
instructions, the entire block will be treated as code. Otherwise it is
treated as a data block.

For example, the bytes in this patch will be treated as code:
```
.byte 0x66
.byte 0x90
```

While these bytes will be treated as data:
```
jmp .L_end
.byte 0x66
.byte 0x90
.L_end:
nop
```

Note that symbolic expressions in `.byte` directives are not currently
supported; the value must be a literal.

## `PassManager` Versus Using `RewritingContext` Directly

The `RewritingContext` object can be used to rewrite a `Module` directly,
without using `PassManager`. This is not recommended for a few reasons:
* Passes provide a mechanism for combining together different transformations
  without getting into the problem of transformation interference.
* GTIRB files can contain multiple modules. Implementing your transform as a
  Pass helps ensure that your transform handles this case by invoking the
  `begin_module`/`end_module` callbacks for each module in the GTIRB IR.

## `register_insert` Versus `insert_at`

`RewritingContext` exposes two ways to insert code: `register_insert` and
`insert_at`. The difference is that insert_at is passed a single location in
the program, where as `register_insert` is passed a scope that is later
resolved into any number of concrete locations. In the future, this will allow
gtirb_rewriting to select insertion locations that have the cheapest cost (as
defined by number of registers spilled, etc).

In general, it is recommended to use `register_insert` if one of the existing
Scopes meets your needs and `insert_at` for any other cases.

## Debug Logging

gtirb_rewriting will log each insertion it applies to its logger at the
DEBUG level. Unless passed a different logger in the PassManager's (or
RewritingContext's) constructor, it will log to the "gtirb_rewriting" logger.

This can be made visible by:
```python
logging.basicConig(format="%(message)s")
logging.getLogger("gtirb_rewriting").setLevel(logging.DEBUG)
```
