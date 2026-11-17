#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Checks generate.py's readers and writers on small fixtures of their own: the Jamfile reader (a
program inside an `if`, a rule's body, the targets a program inherits), the outcome reader (each
directive and section), the Doc Comment reader (a line reference left out), and the writers whose
output a reader of the page sees (inline code that holds a `+` or a backtick, a failing fixture's
output per target, a comparison table's names of code, the decision table's Jamfile column).
generate.py --check proves only that the committed tables are what generate.py writes now: a reader
that regresses and is regenerated in the same change would pass it, and fails here.

Usage: generate_test.py [<case>...]. The doc build runs it before generate.py --check
(doc/Jamfile). Exit 0, or 1 at the first failing case.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import generate  # noqa: E402


def written(directory: Path, name: str, text: str) -> Path:
    """The file name in directory, holding text."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return path


def test_a_rule_body_declares_nothing(scratch: Path) -> None:
    jamfile = written(scratch, 'Jamfile', '# A comment ; with { braces }\n'
                      'rule crypto-run ( name : sources * )\n{\n'
                      '    webcpp.run $(name) : $(sources) ;\n}\n'
                      'crypto-run a : a.cpp ;\n'
                      'webcpp.targets native wasip2 ;\n'
                      'crypto-run b : b.cpp ;\n'
                      'webcpp.run c : c.cpp : : emscripten ;\n')
    assert generate.programs(jamfile) == {'a': ['native'], 'b': ['native', 'wasip2'],
                                          'c': ['emscripten']}, generate.programs(jamfile)


def test_a_program_inside_an_if_is_a_fault(scratch: Path) -> None:
    jamfile = written(scratch, 'Jamfile', 'if $(x)\n{\n    crypto-run a : a.cpp ;\n}\n')
    try:
        generate.statements(jamfile)
    except generate.Fault as fault:
        assert 'inside a block' in str(fault), fault
    else:
        raise AssertionError('a program inside an if was read as declared everywhere')


def test_an_outcome_reads_each_directive(scratch: Path) -> None:
    outcome = generate.Outcome(written(scratch, 'case.outcome', (
        '# A comment\n[all]\ntargets: native wasip2\nbuild: fails\n'
        '# tag::messages[]\n'
        '[native-linux]\ncontains: undefined reference\n'
        'not-contains: warning unless note\n'
        '[wasip2]\ncontains: wasm-ld: error:\n'
        '# end::messages[]\n')))
    assert outcome.targets == ['native', 'wasip2'], outcome.targets
    assert not outcome.succeeds
    assert outcome.contains == [('native-linux', 'undefined reference'),
                                ('wasip2', 'wasm-ld: error:')], outcome.contains
    assert outcome.absent == [('native-linux', 'warning unless note')], outcome.absent
    assert outcome.output == [], outcome.output
    ran = generate.Outcome(written(scratch, 'ran.outcome', (
        'targets: native\nbuild: succeeds\nrun: app\nhello\nworld\n')))
    assert ran.succeeds and ran.output == ['hello', 'world'], (ran.succeeds, ran.output)


def test_a_brief_leaves_out_a_line_reference(scratch: Path) -> None:
    written(scratch, 'include/webcpp/crypto/demo.hpp', (
        'namespace webcpp::crypto {\n'
        '/**\n * Signs a hash (`include/secp256k1.h:235-247`). Then more.\n *\n'
        ' * @return The signature.\n */\nint sign(int hash);\n}\n'))
    operation = {'id': 'demo', 'header': '<webcpp/crypto/demo.hpp>', 'free': True}
    brief = generate.declared_brief(scratch, operation, 'sign')
    assert brief == 'Signs a hash.', brief
    try:
        generate.declared_brief(scratch, operation, 'verify')
    except generate.Fault:
        pass
    else:
        raise AssertionError('a function no header declares was given a brief')


def test_code_that_holds_a_plus_is_one_span(_: Path) -> None:
    # `+em++: error:+` would be read as `+em+` and a stray rest: the text is a passthrough.
    assert generate.code('em++: error:') == '`pass:[em++: error:]`', generate.code('em++')
    assert generate.code('a[1]+<b>') == '`pass:[a[1\\]+&lt;b&gt;]`', generate.code('a[1]+<b>')
    # A backtick is the reference the page keeps for it: a literal one would read as two spans.
    assert generate.code("to `x'") == "`pass:[to &#96;x']`", generate.code("to `x'")
    assert generate.code('wasm-ld: error:') == '`+wasm-ld: error:+`'


def test_a_failing_fixture_lists_its_texts_per_target(scratch: Path) -> None:
    data = {'outcome_sections': {'all': 'every target', 'wasip2': 'wasip2',
                                 'native-linux': 'native, Linux'}}
    outcome = generate.Outcome(written(scratch, 'case.outcome', (
        'targets: native wasip2\nbuild: fails\n[native-linux]\ncontains: one\ncontains: two\n'
        '[wasip2]\ncontains: em++: error:\n')))
    assert generate.printed(data, outcome) == ('* native, Linux:\n** `+one+`\n** `+two+`\n'
                                               '* wasip2:\n** `pass:[em++: error:]`'), (
        generate.printed(data, outcome))
    every = generate.Outcome(written(scratch, 'every.outcome', (
        'targets: emscripten\nbuild: fails\ncontains: no backend\n')))
    assert generate.printed(data, every) == '* emscripten:\n** `+no backend+`', (
        generate.printed(data, every))
    unknown = generate.Outcome(written(scratch, 'unknown.outcome', (
        'build: fails\n[native-windows]\ncontains: LNK2001\n')))
    try:
        generate.printed(data, unknown)
    except generate.Fault as fault:
        assert 'native-windows' in str(fault), fault
    else:
        raise AssertionError('a section with no label was printed')


def test_a_fixture_that_builds_and_runs_nothing_is_a_record(scratch: Path) -> None:
    # A misuse that only MSVC's linker stops builds elsewhere: its fixture says build: succeeds
    # with no run:. It is no program of the Jamfiles page; the messages page lists it after
    # MSVC's cases, its Jamfile included, and needs no output region.
    data = {'outcome_sections': {'all': 'every target'}, 'sources': {}, 'fixes': {},
            'fixtures': {'program': 'A program.', 'record': 'Two files, one with an option.'}}
    program = generate.Outcome(written(scratch, 'program.outcome', (
        'targets: native\nbuild: succeeds\nrun: app\nhello\n')))
    record = generate.Outcome(written(scratch, 'record.outcome', (
        'targets: native\nbuild: succeeds\n')))
    assert program.runs and not record.runs, (program.runs, record.runs)
    cases = {'program': ([], program), 'record': ([], record)}
    programs = generate.jamfiles_page(data, cases)
    assert '`+program+`' in programs and 'record' not in programs, programs
    messages = generate.messages_page(data, {}, cases, {})
    assert '`+record+`:: Two files, one with an option.' in messages, messages
    assert 'record/Jamfile[tag=jamfile]' in messages and 'program' not in messages, messages


def test_a_comparison_column_is_headed_by_its_plain_name(_: Path) -> None:
    data = {'sources': {}, 'namespaces': {'ciphers': {
        'columns': ['Algorithm', 'AEAD'],
        'rows': [['`gcm`, `aes256_gcm`: AES-GCM', 'yes'], ['`aes256`', 'no']]}}}
    page = generate.namespace_page(data, 'ciphers')
    assert '|Algorithm |AES-GCM |`aes256`\n' in page, page
    assert '|Names\n|`gcm`, `aes256_gcm`\n|\n' in page, page


def test_the_decision_table_writes_no_jamfile_as_prose(scratch: Path) -> None:
    written(scratch, 'example/app.cpp', '')
    entry = {'need': 'n', 'namespace': 'webcpp::crypto', 'api': '`f`', 'backend': 'b',
             'example': 'app', 'section': 's'}
    page = generate.use_cases_page({'use_cases': [
        dict(entry, jamfile='none'), dict(entry, jamfile='/webcpp/crypto//crypto'),
        dict(entry, jamfile='/webcpp/crypto//crypto /third_party//ctaes'),
        dict(entry, jamfile="`/webcpp/crypto//crypto` brings Boost's headers")]}, scratch)
    assert page.startswith('[.key-column,cols="3,3,2,3,2",options="header"]\n'), page
    assert '\n|none\n' in page, page
    # Each target on a line of its own, a path that breaks after a /, as a header's does, where
    # the table does not fit otherwise; an example's file, which a reader copies, stays whole
    # (the role keep). The other names of the table break after their :: first, then between
    # their parts.
    assert '\n|`+/webcpp/crypto//crypto+`\n' in page, page
    assert '\n|`+/webcpp/crypto//crypto+` +\n`+/third_party//ctaes+`\n' in page, page
    assert "\n|`+/webcpp/crypto//crypto+` brings Boost's headers\n" in page, page
    assert '\n|<<s,[.keep]`+app.cpp+`>>\n' in page, page


CASES: list[Callable[[Path], None]] = [
    test_a_rule_body_declares_nothing,
    test_a_program_inside_an_if_is_a_fault,
    test_an_outcome_reads_each_directive,
    test_a_brief_leaves_out_a_line_reference,
    test_code_that_holds_a_plus_is_one_span,
    test_a_failing_fixture_lists_its_texts_per_target,
    test_a_fixture_that_builds_and_runs_nothing_is_a_record,
    test_a_comparison_column_is_headed_by_its_plain_name,
    test_the_decision_table_writes_no_jamfile_as_prose,
]


def main(argv: list[str]) -> int:
    unknown = set(argv) - {case.__name__ for case in CASES}
    if unknown:
        print(f'generate_test: no case named {", ".join(sorted(unknown))}', file=sys.stderr)
        return 2
    for case in CASES:
        if argv and case.__name__ not in argv:
            continue
        with tempfile.TemporaryDirectory(prefix='generate test ') as scratch:
            case(Path(scratch))
        print(f'{case.__name__}: ok')
    print('generate_test: ok')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
