import gtirb
import gtirb_rewriting
from gtirb_rewriting.assembler import _Assembler
from helpers import add_proxy_block, add_symbol, create_test_module


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


def test_symbolic_expr():
    ir, m, bi = create_test_module()
    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    assembler = _Assembler(m, 0, {})
    assembler.assemble(
        "call puts", gtirb_rewriting.X86Syntax.INTEL,
    )
    assembler.finalize()

    assert len(assembler.symbolic_expressions) == 1
    sym_expr = assembler.symbolic_expressions[1]
    assert isinstance(sym_expr, gtirb.SymAddrConst)
    assert sym_expr.symbol == puts_sym
    assert sym_expr.offset == 0
    assert sym_expr.attributes == {gtirb.SymbolicExpression.Attribute.PltRef}


def test_symbolic_expr_sym_offset():
    ir, m, bi = create_test_module()
    puts_sym = add_symbol(m, "puts", add_proxy_block(m))

    assembler = _Assembler(m, 0, {})
    assembler.assemble(
        "inc byte ptr [puts + 42]", gtirb_rewriting.X86Syntax.INTEL,
    )
    assembler.finalize()

    assert len(assembler.symbolic_expressions) == 1
    sym_expr = assembler.symbolic_expressions[3]
    assert isinstance(sym_expr, gtirb.SymAddrConst)
    assert sym_expr.symbol == puts_sym
    assert sym_expr.offset == 42
    assert sym_expr.attributes == {gtirb.SymbolicExpression.Attribute.GotRelPC}
