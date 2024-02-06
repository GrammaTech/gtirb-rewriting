# Deletion Details

## Deleting Instructions and Bytes

gtirb-rewriting supports deleting instructions in a code block or bytes from a
data block using `delete_at`. It attempts to model this as closely as possible
to deleting the relevant lines from the pretty-printed assembly file.

For example, deleting a call instruction in code block will cause control to
flow into the subsequent block and gtirb-rewriting will update the CFG to
model that.

## Deleting Whole Blocks

Deleting a whole block is done by deleting all of the bytes in the block with
`delete_at` and also behaves as if those lines were deleted from the
pretty-printed assembly file. Notably this means that symbols, control flow,
and other constructs do not get removed but instead moved to be attached to
another block.

For example, given this assembly:
```asm
foo:
nop

bar:
ret
```

Deleting all of the `foo` block results in the symbol being attached to the
subsequent block:
```asm
foo:
bar:
ret
```

This introduces a handful of edge cases that gtirb-rewriting has to deal with,
largely around what to do when there isn't an obvious next (or previous) block
to move symbols and control flow to.

In such cases, gtirb-rewriting may need to leave a zero-sized block in the IR
to avoid losing information. Currently, this can happen if:
- There are symbols attached to the block, but there are no other blocks in
  the section to move them to.
- The block has incoming control flow, but there isn't a subsequent block in
  section or the subsequent block is not a code block.
- The block being deleted has important CFI directives (directives that do not
  model side effects of instructions being deleted, e.g. `.cfi_startproc`) but
  there's no code block to move them to, either because there aren't any other
  bocks in the section or because the adjacent blocks are both data blocks.

## The `retarget_to_proxy` Parameter

`delete_at` takes an optional parameter, `retarget_to_proxy`, that can be used
to influence how the deletion handles symbols and control flow edges. If this
is set to `True`, a new proxy block will be created that any symbols will be
moved to and any incoming control flow will be redirected to.

This parameter can only be used when deleting a whole block and will cause
an exception to be raised when deleting only part of a block.

## Deleting Whole Functions

The `delete_function` method deletes every block in the function and retargets
symbols and control flow to proxy blocks. This effectively turns the function
into an external function, which may cause link errors if it is still used.
