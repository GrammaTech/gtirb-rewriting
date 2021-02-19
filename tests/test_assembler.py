import gtirb
import gtirb_rewriting
from gtirb_rewriting.assembler import _Assembler


def test_return_edges():
    m = gtirb.Module(
        isa=gtirb.Module.ISA.X64,
        file_format=gtirb.Module.FileFormat.ELF,
        name="test",
    )
    assembler = _Assembler(m, 0, {})
    assembler.assemble(
        "ret", gtirb_rewriting.X86Syntax.INTEL,
    )
    assembler.finalize()

    assert len(assembler.blocks) == 2
    assert assembler.blocks[0].offset == 0
    assert assembler.blocks[0].size == 1
    assert assembler.blocks[1].offset == 1
    assert assembler.blocks[1].size == 0

    edges = list(assembler.cfg.out_edges(assembler.blocks[0]))
    assert len(edges) == 1
    assert edges[0].label.type == gtirb.Edge.Type.Return
    assert isinstance(edges[0].target, gtirb.ProxyBlock)
    assert edges[0].target in assembler.proxies

    assert assembler.data == b"\xC3"
