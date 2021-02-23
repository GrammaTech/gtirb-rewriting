# gtirb-rewriting

## Overview

The gtirb-rewriting package provides a Python API for rewriting GTIRB files.

## Getting Started

See the documentation in the [Getting Started guide](doc/Getting-Started.md).

## Design

A `Pass` registers changes to be made in a module with the `RewritingContext`
passed to `begin_module`.

When using `RewritingContext.register_insert`, each change has a given `Scope`
and a `Patch` to apply. The `Scope` allows the pass to declaratively state
where the patch should be applied. Currently supported are:
* `AllBlocksScope` to insert in every basic block
* `AllFunctionsScope` to insert into every function's entry blocks or exit
   blocks.
* `SingleBlockScope` to insert at a specific block

Alternatively, `RewritingContext.insert_at` and `RewritingConext.replace_at`
take an exact location of function / block / offset to insert at.

A `Patch` consists of a method to generate an assembly string and a
`Constraints` object that describes metadata about the assembly (e.g. what
registers it clobbers or how many scratch registers it needs).

Once all changes from all passes have been registered, the rewriting context
finds concrete insertion locations to insert the patch into. This is based
off of the scope requested and the constraints in the patch. If the scope
allows it, the rewriting context may attempt to find a location that is
cheaper (e.g. requires no register spills). This is called bubbling.

After resolving the concrete insertion location, the patch is asked to
generate its assembly code. The assembly is then assembled to machine code and
inserted into the GTIRB representation. If the assembly refers to any symbols,
the rewriting API will look them up in the GTIRB module's symbol table
(asserting that they exist) and create the appropriate symbolic expressions.
Also, if the patch's constraints require additional work like aligning the
stack or spilling to free up the requested scratch register, this code will be
generated at this point.

A pass may optionally be called back after all patches have been applied with
the `end_module` method. This provides an opportunity to do per-module work,
such as writing an edge map for a profiling pass.

## Copyright and Acknowledgments

Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the GPLv3 license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.
