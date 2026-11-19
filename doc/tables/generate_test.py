#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Checks generate.py's readers and writers on small fixtures of their own: the Jamfile reader (a
program inside an `if`, a rule's body, the targets a program inherits, the memory option's tests, a
name declared twice), a backend's reason for the targets an operation misses (OpenSSL's alone), the
outcome reader (each directive and section), the Doc Comment reader (a line reference left out), the
writers whose output a reader of the page sees (inline code that holds a `+` or a backtick, a
failing fixture's output per target, a comparison table's names of code, the decision table's
Jamfile column, the table of Ed25519's edge cases, a family's measured constant time per target, a
lane note of one checker beside that checker alone, a comparison table's columns, its measured
cells and its refusal of a fact without a source, the decision table's link to its example,
llms.txt's entry of a function, every backend's facts and own suite, every API page's default per
target),
and the capability table's: its checks of
crypto.json's families, the refusals and cells of include/webcpp/crypto/detail/capabilities.hpp, the
cells test/capabilities_test.cpp asserts, and the comparison --check makes; and the size matrix's:
what each cell adds to the baseline per target, read from the lane sizes' tables (generate.py
--sizes), "not measured yet" where the lane has not built it, and the refusal of a table not built
at release, of a program measured twice or of no cell, and of doc/tables/sizes.json edited by hand.
generate.py --check proves only that the committed tables are what generate.py writes now: a reader
that regresses and is regenerated in the same change would pass it, and fails here.

Usage: generate_test.py [<case>...]. The doc build runs it before generate.py --check
(doc/Jamfile). Exit 0, or 1 at the first failing case.
"""

from __future__ import annotations

import io
import sys
import tempfile
from contextlib import redirect_stderr
from collections.abc import Callable
from pathlib import Path
from typing import Optional

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


def test_the_memory_option_s_tests_are_declared(scratch: Path) -> None:
    # The OpenSSL memory option's programs live in test/openssl_memory, each through its own
    # rule; a name that two Jamfiles declare is a fault, since a table would cite one of them.
    written(scratch, 'test/Jamfile', 'webcpp.targets native wasip2 ;\ncrypto-run a : a.cpp ;\n')
    written(scratch, 'test/openssl_memory/Jamfile', (
        'webcpp.targets native ;\n'
        'rule memory-run ( name : sources + : requirements * )\n{\n'
        '    webcpp.run $(name) : $(sources) : $(requirements) ;\n}\n'
        'memory-run late : late_test.cpp : <threading>multi ;\n'))
    found = generate.tests(scratch)
    assert found == {'a': ['native', 'wasip2'], 'late': ['native']}, found
    written(scratch, 'test/openssl_memory/Jamfile', 'memory-run a : a_test.cpp ;\n')
    try:
        generate.tests(scratch)
    except generate.Fault as fault:
        assert 'a' in str(fault) and 'twice' in str(fault), fault
    else:
        raise AssertionError('a test declared twice was read as one')


def test_a_backend_says_why_it_is_missing_elsewhere(_: Path) -> None:
    # OpenSSL's operations are missing where /webcpp/crypto//openssl stops the build, unless
    # the operation names its own reason: the memory option is refused on every WebAssembly
    # target, wasip2 and wasip3 included, where OpenSSL itself builds.
    data = {'targets': ['native', 'wasip2', 'emscripten'],
            'elsewhere': {'openssl': 'the build stops', 'memory': 'config.hpp refuses it'},
            'operations': [
                {'id': 'gcm', 'backends': {'openssl': {'tests': ['g']}}},
                {'id': 'memory', 'backends': {'openssl': {'tests': ['m'],
                                                           'elsewhere': 'memory'}}}]}
    matrix = generate.Matrix(data, {'g': ['native', 'wasip2'], 'm': ['native']}, {})
    assert matrix.targets('gcm', 'openssl') == 'native, wasip2; not on emscripten: the build stops'
    assert matrix.targets('memory', 'openssl') == (
        'native; not on wasip2, emscripten: config.hpp refuses it'), matrix.targets('memory',
                                                                                   'openssl')


def test_a_reason_elsewhere_is_openssl_s_alone(_: Path) -> None:
    # Only OpenSSL's cells say why an operation is missing on a target; a reason on another
    # backend's entry would be read and never shown, so it is a fault.
    data = {'targets': ['native', 'wasip2'],
            'elsewhere': {'openssl': 'the build stops', 'memory': 'config.hpp refuses it'},
            'operations': [{'id': 'gcm', 'backends': {'bearssl': {'tests': ['g'],
                                                                  'elsewhere': 'memory'}}}]}
    try:
        generate.Matrix(data, {'g': ['native']}, {})
    except generate.Fault as fault:
        assert 'gcm on bearssl' in str(fault) and 'memory' in str(fault), fault
    else:
        raise AssertionError('a reason elsewhere on bearssl was read and never shown')


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


def test_a_qualified_function_is_read_in_its_class(scratch: Path) -> None:
    written(scratch, 'include/webcpp/crypto/two.hpp', (
        'namespace webcpp::crypto {\n'
        'class key {\npublic:\n    /** Signs a message. */\n    int sign(int message);\n};\n'
        'class signer {\n    struct inner {\n        /** Not this one. */\n'
        '        int other(int x);\n    };\n\npublic:\n'
        '    /** Signs the message given in pieces. */\n    int sign(int key);\n};\n}\n'))
    operation = {'id': 'two', 'header': '<webcpp/crypto/two.hpp>'}
    assert generate.declared_brief(scratch, operation, 'sign') == 'Signs a message.'
    brief = generate.declared_brief(scratch, operation, 'signer::sign')
    assert brief == 'Signs the message given in pieces.', brief
    try:
        generate.declared_brief(scratch, operation, 'nothing::sign')
    except generate.Fault:
        pass
    else:
        raise AssertionError('a function of a class no header defines was given a brief')


def test_an_index_entry_names_a_qualified_function_bare(scratch: Path) -> None:
    # llms.txt lists a class's functions under the class: `signer::sign` is read in its class
    # and written `sign`, as every other entry is.
    written(scratch, 'include/webcpp/crypto/two.hpp', (
        'namespace webcpp::crypto {\n'
        'class key {\npublic:\n    /** Signs a message. */\n    int sign(int message);\n};\n'
        'class signer {\npublic:\n'
        '    /** Signs the message given in pieces. */\n    int sign(int key);\n};\n}\n'))
    operation = {'id': 'two', 'header': '<webcpp/crypto/two.hpp>'}
    entry = generate.llms_entry(scratch, operation, 'signer::sign')
    assert entry == '  - sign: Signs the message given in pieces.', entry
    entry = generate.llms_entry(scratch, operation, 'sign')
    assert entry == '  - sign: Signs a message.', entry


def test_the_edge_cases_table_has_a_row_per_case_and_a_column_per_verdict(_: Path) -> None:
    data = {'backends': {'sodium': {'title': 'libsodium'}}}
    cases = {'source': {'repository': 'novifinancial/ed25519-speccheck', 'commit': '65519336',
                        'file': 'cases.json'},
             'backends': {'sodium': {'raw': ['reject', 'accept'], 'strict': ['reject', 'accept']}},
             'outside': {'webcrypto-node': {'node': '26.13.0', 'openssl': '4.1.0',
                                            'verdicts': ['accept', 'accept']}},
             'cases': ['`S` = 0', '`A` non-canonical']}
    page = generate.ed25519_cases_page(data, cases)
    header = ('|Case |What it tests |libsodium, raw |libsodium, strict '
              '|WebCrypto in node 26.13.0 (OpenSSL 4.1.0), outside view')
    assert header in page, page
    assert '\n|0\n|`+S+` = 0\n|reject\n|reject\n|accept\n' in page, page
    assert '\n|1\n|`+A+` non-canonical\n|accept\n|accept\n|accept\n' in page, page
    for broken in ({'raw': ['reject'], 'strict': ['reject', 'accept']},
                   {'raw': ['reject', 'maybe'], 'strict': ['reject', 'accept']}):
        try:
            generate.ed25519_cases_page(data, {**cases, 'backends': {'sodium': broken}})
        except generate.Fault:
            pass
        else:
            raise AssertionError(f'a row {broken} was written')


def test_an_edge_cases_key_the_generator_does_not_know_is_a_fault(_: Path) -> None:
    # A backend misnamed, an outside view without a title, or one whose node or OpenSSL is not
    # recorded would leave the page silently short of a row or of its provenance.
    data = {'backends': {'sodium': {'title': 'libsodium'}}}
    row = {'raw': ['reject'], 'strict': ['reject']}
    view = {'node': '26.13.0', 'openssl': '4.1.0', 'verdicts': ['reject']}
    for backends, outside in (({'libsodium': row}, {'webcrypto-node': view}),
                              ({'sodium': row}, {'webcrypto-deno': view}),
                              ({'sodium': row}, {'webcrypto-node': {'verdicts': ['reject']}})):
        cases = {'backends': backends, 'outside': outside, 'cases': ['`S` = 0']}
        try:
            generate.ed25519_cases_page(data, cases)
        except generate.Fault:
            pass
        else:
            raise AssertionError(f'the keys {backends}, {outside} were written')


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
    page = generate.namespace_page(data, 'ciphers', {'cases': []})
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


EVERY_TARGET = ['native', 'wasip2', 'wasip3', 'emscripten']


def small_table() -> generate.Data:
    """A capability table of one family, Ed25519, on libsodium alone, beside BearSSL and a
    backend that is no tag of `backends` (the operating system's generator)."""
    def backend(title: str, name: str, jamfile: str) -> generate.Data:
        return {'title': title, 'jamfile': jamfile, 'without_b2': f'link {title}',
                'header': f'<webcpp/crypto/backends/{name}.hpp>', 'targets': EVERY_TARGET}
    return {
        'targets': EVERY_TARGET, 'sources': {'rfc8032': ['RFC 8032', 'https://example.org']},
        'compilers': {'clang': 'Clang', 'gcc': 'GCC', 'msvc': 'MSVC'},
        'backends': {'bearssl': backend('BearSSL', 'bearssl', '/third_party//bearssl'),
                     'sodium': backend('libsodium', 'sodium', '/third_party//sodium'),
                     'system': {'title': 'The system'}},
        'operations': [{'id': 'sign', 'family': 'ed25519',
                        'backends': {'sodium': {'tests': ['ed25519']}}}],
        'families': [{
            'name': 'ed25519', 'title': 'Ed25519', 'group': 'curves::ed25519', 'since': '0.2',
            'header': '<webcpp/crypto/curves/ed25519.hpp>',
            'names': [{'name': 'ed25519', 'title': 'Ed25519',
                       'type': 'curves::ed25519::basic_keypair<{backend}>'}],
            'default': [{'targets': EVERY_TARGET, 'backend': 'sodium', 'tests': ['ed25519'],
                         'why': 'the only backend ({rfc8032})'}],
            'backends': {'sodium': {'targets': 'all'}}}]}


def a_fault(data: generate.Data, declared: dict[str, list[str]], wanted: str) -> None:
    """Checks that the families of data are refused with a fault that says wanted."""
    try:
        generate.check_families(data, declared)
    except generate.Fault as fault:
        assert wanted in str(fault), fault
    else:
        raise AssertionError(f'no fault saying {wanted}')


def test_a_backend_without_a_family_is_refused_naming_those_that_have_it(_: Path) -> None:
    header = generate.capabilities_header(small_table())
    assert ('static_assert(!std::is_same_v<Backend, ::webcpp::crypto::backends::bearssl>, '
            '"webcpp::crypto: bearssl has no Ed25519. The backends that have it: sodium '
            '(native, wasip2, wasip3, emscripten).")') in header, header
    # A backend that has the family, whose header the program did not include, is told so; a
    # backend that is no tag of backends:: is never named; any other type is the last refusal.
    assert ('!::webcpp::crypto::detail::linked<::webcpp::crypto::backends::sodium>, '
            '"webcpp::crypto: sodium\'s Ed25519 is in <webcpp/crypto/backends/sodium.hpp>, '
            'which the program does not include. Include it, and add /third_party//sodium to the '
            'program\'s Jamfile.")') in header, header
    assert 'system' not in header, header
    assert ('static_assert(std::is_same_v<Backend, ::webcpp::crypto::backends::bearssl> || '
            'std::is_same_v<Backend, ::webcpp::crypto::backends::sodium>, '
            '"webcpp::crypto: Ed25519 has no backend of that name. The backends that have it: '
            'sodium (native, wasip2, wasip3, emscripten).")\n') in header, header
    assert '#define WEBCPP_CRYPTO_DETAIL_REFUSE_ED25519(Backend)' in header, header


def test_a_cell_decided_at_run_time_says_so(_: Path) -> None:
    data = small_table()
    data['families'][0]['backends']['sodium'] = {'targets': ['native'], 'runtime': True}
    assert generate.refusal(data, data['families'][0], 'bearssl') == (
        'webcpp::crypto: bearssl has no Ed25519. The backends that have it: sodium (native, at '
        'run time).')


def test_each_cell_is_true_on_its_targets_alone(_: Path) -> None:
    data = small_table()
    data['families'][0]['backends']['sodium']['targets'] = ['native', 'wasip3']
    header = generate.capabilities_header(data)
    assert ('#if defined(WEBCPP_CRYPTO_DETAIL_TARGET_NATIVE) || defined(WEBCPP_TARGET_WASIP3)\n'
            'template <>\n'
            'inline constexpr bool supported<families::ed25519, families::ed25519, '
            'backends::sodium> = true;\n#endif\n') in header, header
    # A family of one name is its own name: no tag of tags:: is declared for it.
    assert 'struct ed25519;' in header and 'namespace webcpp::crypto::tags' not in header, header
    assert header.startswith('#ifndef WEBCPP_CRYPTO_DETAIL_CAPABILITIES_HPP\n'), header


def test_the_generated_test_asserts_every_cell(_: Path) -> None:
    test = generate.capabilities_test(small_table())
    present = ('crypto::supports_v<algorithm<families::ed25519, families::ed25519>, '
               'backends::sodium>')
    assert (f'#if defined(WEBCPP_CRYPTO_DETAIL_TARGET_NATIVE) || defined(WEBCPP_TARGET_WASIP2) '
            f'|| defined(WEBCPP_TARGET_WASIP3) || defined(WEBCPP_TARGET_EMSCRIPTEN)\n'
            f'static_assert({present});\n#else\nstatic_assert(!{present});\n#endif\n') in test, test
    assert ('static_assert(!crypto::supports_v<algorithm<families::ed25519, families::ed25519>, '
            'backends::bearssl>);\n') in test, test
    # Each present cell is made, where its backend is linked, through the family's own type.
    assert ('defined(WEBCPP_CRYPTO_HAS_SODIUM)\n    BOOST_TEST((webcpp::test::made<'
            'crypto::curves::ed25519::basic_keypair<backends::sodium>, families::ed25519, '
            'families::ed25519, backends::sodium>()));\n') in test, test
    assert '#include <webcpp/crypto/curves/ed25519.hpp>\n' in test, test
    assert '#ifdef WEBCPP_CRYPTO_HAS_SODIUM\n#include <webcpp/crypto/backends/sodium.hpp>\n' in (
        test), test
    # The refusal macro is parsed, in a template no one instantiates.
    assert 'WEBCPP_CRYPTO_DETAIL_REFUSE_ED25519(Backend);' in test, test


def test_a_family_that_names_an_unknown_backend_is_a_fault(_: Path) -> None:
    data = small_table()
    data['families'][0]['backends']['botan'] = {'targets': 'all'}
    a_fault(data, {'ed25519': EVERY_TARGET},
            'the family ed25519 names the backend botan, which is no tag of backends')
    data = small_table()
    data['families'][0]['backends']['system'] = {'targets': 'all'}
    a_fault(data, {'ed25519': EVERY_TARGET},
            'the family ed25519 names the backend system, which is no tag of backends')


def test_a_cell_claimed_where_no_test_runs_is_a_fault(_: Path) -> None:
    a_fault(small_table(), {'ed25519': ['native', 'wasip2', 'wasip3']},
            'the family ed25519 claims sodium on emscripten, where no test of its operations '
            'on sodium runs')
    data = small_table()
    data['backends']['sodium']['targets'] = ['native']
    data['families'][0]['backends']['sodium']['targets'] = ['native', 'wasip2']
    a_fault(data, {'ed25519': EVERY_TARGET},
            'the family ed25519 claims sodium on wasip2, where sodium is not built')


def a_default(targets: list[str], backend: Optional[str],
              compilers: Optional[list[str]] = None,
              tests: Optional[list[str]] = None) -> generate.Data:
    """A row of a family's defaults, on targets, for the compilers named, else for every one."""
    row: generate.Data = {'targets': targets, 'backend': backend,
                          'tests': ['ed25519'] if tests is None else tests, 'why': 'w'}
    if compilers is not None:
        row['compilers'] = compilers
    return row


def test_a_default_is_a_backend_of_the_family_its_tests_run_on(_: Path) -> None:
    data = small_table()
    every = {'ed25519': EVERY_TARGET, 'ed25519_native': ['native']}
    data['families'][0]['default'] = [a_default(['native'], 'sodium')]
    a_fault(data, every, 'the family ed25519 has no default on wasip2, wasip3, emscripten')
    data['families'][0]['default'] = [a_default(EVERY_TARGET, 'bearssl')]
    a_fault(data, every,
            'the family ed25519 defaults to bearssl on native, which does not have it there')
    data['families'][0]['default'] = [a_default(EVERY_TARGET, 'sodium'),
                                      a_default(['native'], 'sodium')]
    a_fault(data, every, 'the family ed25519 has two defaults on native')
    # A compiler's row restates its target's default with a reason of its own; it never changes
    # the backend, which the target alone chooses.
    wasm = ['wasip2', 'wasip3', 'emscripten']
    data['families'][0]['default'] = [a_default(wasm, 'sodium'),
                                      a_default(['native'], 'sodium', ['clang', 'gcc']),
                                      a_default(['native'], 'sodium', ['msvc'])]
    generate.check_families(data, every)
    data['families'][0]['default'] = [a_default(wasm, 'sodium'),
                                      a_default(['native'], 'sodium', ['clang', 'gcc']),
                                      a_default(['native'], None, ['msvc'])]
    a_fault(data, every, 'the family ed25519 has two default backends on native, sodium and '
            'none: the target alone chooses it')
    # The compilers are names of crypto.json's compilers, so that two rows cannot name one
    # compiler in two spellings: each compiler of a target has one row.
    data['families'][0]['default'] = [a_default(wasm, 'sodium'),
                                      a_default(['native'], 'sodium', ['Clang and GCC']),
                                      a_default(['native'], 'sodium', ['msvc'])]
    a_fault(data, every, 'the family ed25519\'s default on native names the compiler Clang and '
            'GCC, which crypto.json\'s compilers does not list')
    data['families'][0]['default'] = [a_default(wasm, 'sodium'),
                                      a_default(['native'], 'sodium', ['clang', 'gcc']),
                                      a_default(['native'], 'sodium', ['gcc', 'msvc'])]
    a_fault(data, every, 'the family ed25519 has two defaults on native with gcc')
    data['families'][0]['default'] = [a_default(EVERY_TARGET, 'sodium'),
                                      a_default(['native'], 'sodium', ['msvc'])]
    a_fault(data, every, 'the family ed25519 has two defaults on native with msvc')
    data['families'][0]['default'] = [a_default(wasm, 'sodium'),
                                      a_default(['native'], 'sodium', ['clang']),
                                      a_default(['native'], 'sodium', ['msvc'])]
    a_fault(data, every, 'the family ed25519 has no default on native with gcc')
    # A default is claimed only where a test that fixes it runs.
    data['families'][0]['default'] = [a_default(EVERY_TARGET, 'sodium',
                                                tests=['ed25519_native'])]
    a_fault(data, every, 'the family ed25519\'s default on wasip2 names the test ed25519_native, '
            'which does not run there')
    data['families'][0]['default'] = [a_default(EVERY_TARGET, 'sodium', tests=['absent'])]
    a_fault(data, every, 'the family ed25519\'s default on native names the test absent, which '
            'does not run there')
    data = small_table()
    data['operations'][0]['family'] = 'ed448'
    a_fault(data, {'ed25519': EVERY_TARGET},
            'the operation sign names the family ed448, which crypto.json does not list')


def two_backends() -> generate.Data:
    """small_table with BearSSL's Ed25519 on every target, and libsodium the default natively
    alone, BearSSL elsewhere."""
    data = small_table()
    family = data['families'][0]
    family['backends']['bearssl'] = {'targets': 'all'}
    family['shown'] = 'ed25519'
    family['default'] = [a_default(['native'], 'sodium'),
                         a_default(['wasip2', 'wasip3', 'emscripten'], 'bearssl')]
    return data


def test_the_defaults_header_chooses_by_the_target_alone(_: Path) -> None:
    header = generate.defaults_header(two_backends())
    assert header.startswith('#ifndef WEBCPP_CRYPTO_DETAIL_DEFAULTS_HPP\n'), header
    assert '#include <webcpp/crypto/detail/capabilities.hpp>\n' in header, header
    assert ('template <class Family>\nstruct default_backend_of {};\n') in header, header
    assert ('#ifdef WEBCPP_CRYPTO_DETAIL_TARGET_NATIVE\n'
            '/** Defined where libsodium is the default of Ed25519. */\n'
            '#define WEBCPP_CRYPTO_DETAIL_DEFAULT_ED25519_SODIUM 1\n'
            '/** The default of Ed25519 on native: libsodium. */\n'
            'template <>\nstruct default_backend_of<families::ed25519> {\n'
            '    /** `backends::sodium`. */\n    using type = backends::sodium;\n};\n'
            '#elif defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3) || '
            'defined(WEBCPP_TARGET_EMSCRIPTEN)\n') in header, header
    assert 'using type = backends::bearssl;\n};\n#endif\n' in header, header
    assert ('template <class Family>\n'
            'using default_backend_t = default_backend_of<Family>::type;\n') in header, header
    # AES-GCM's default keeps version 0.1's name, default_backend; a table without it has none.
    assert 'using default_backend =' not in header, header
    # A family whose default is the same on every target needs no condition.
    one = generate.defaults_header(small_table())
    assert ('#define WEBCPP_CRYPTO_DETAIL_DEFAULT_ED25519_SODIUM 1\n/** The default of Ed25519 '
            'on native, wasip2, wasip3, emscripten: libsodium. */\n') in one, one
    assert '#if' not in one.split('struct default_backend_of {};', 1)[1], one


def test_the_other_backend_a_refusal_names_is_chosen_as_stated(_: Path) -> None:
    # The other backend is the first of crypto.json's backends, not of the family's, that has
    # the family on the target when the program is built; the type is the family's shown name.
    data = two_backends()
    family = data['families'][0]
    family['backends'] = {'sodium': {'targets': 'all'}, 'bearssl': {'targets': 'all'}}
    family['names'].append({'name': 'ed25519ph', 'title': 'Ed25519ph',
                            'type': 'curves::ed25519ph::keypair<{backend}>'})
    text = generate.needs(data, family, 'native', 'sodium')
    assert 'as in curves::ed25519::basic_keypair<backends::bearssl>.' in text, text
    # A backend that has the family only at run time is never offered in its place.
    family['backends']['bearssl'] = {'targets': 'all', 'runtime': True}
    text = generate.needs(data, family, 'native', 'sodium')
    assert 'and the one backend that has it there' in text, text
    assert 'name another backend' not in text, text
    # A family whose default has another backend must say which name its refusal shows.
    family['backends']['bearssl'] = {'targets': 'all'}
    data['operations'][0]['backends']['bearssl'] = {'tests': ['ed25519']}
    del family['shown']
    a_fault(data, {'ed25519': EVERY_TARGET}, 'the family ed25519 has no shown name, which its '
            'default\'s refusal names with another backend')
    family['shown'] = 'ed448'
    a_fault(data, {'ed25519': EVERY_TARGET}, 'the family ed25519 shows ed448, which is none of '
            'its names')


def test_a_row_of_some_compilers_is_labelled_with_their_names(_: Path) -> None:
    data = small_table()
    assert generate.target_label(data, a_default(['native'], 'sodium', ['clang', 'gcc'])) == (
        'native, Clang and GCC')
    assert generate.target_label(data, a_default(['native'], 'sodium', ['msvc'])) == (
        'native, MSVC')
    assert generate.target_label(data, a_default(['wasip2', 'wasip3'], 'sodium')) == (
        'wasip2, wasip3')


def test_each_family_s_default_has_an_alias_that_links_it_per_target(_: Path) -> None:
    block = generate.default_aliases(two_backends())
    assert block.startswith(generate.ALIASES_BEGIN + '\n'), block
    assert block.endswith(generate.ALIASES_END + '\n'), block
    assert ('rule ed25519-default-linked ( properties * )\n{\n'
            '    switch [ webcpp-target.target-of $(properties) ]\n    {\n'
            '        case native : return <library>/third_party//sodium ;\n'
            '        case wasip2 : return <library>/third_party//bearssl ;\n'
            '        case wasip3 : return <library>/third_party//bearssl ;\n'
            '        case emscripten : return <library>/third_party//bearssl ;\n'
            '    }\n}\n'
            'alias ed25519-default : : : : <conditional>@ed25519-default-linked ;\n') in block, (
        block)
    # A family without a default has no alias.
    data = small_table()
    data['families'][0]['default'] = [a_default(EVERY_TARGET, None)]
    assert 'rule' not in generate.default_aliases(data), generate.default_aliases(data)
    # The block replaces the one of build.jam, whose other lines stay as they are.
    old = f'head\n{generate.ALIASES_BEGIN}\nold\n{generate.ALIASES_END}\ntail\n'
    assert generate.with_aliases(old, block) == f'head\n{block}tail\n'
    try:
        generate.with_aliases('no block\n', block)
    except generate.Fault as fault:
        assert 'build.jam has no block' in str(fault), fault
    else:
        raise AssertionError('a build.jam without the block was accepted')


def test_each_alias_has_a_row_and_a_fixture_that_runs_it_where_its_family_has_a_default(
        scratch: Path) -> None:
    # The page's table of the aliases: per family with a default, its alias, the library it links
    # on each target and the fixture of the user's Jamfiles that builds and runs it,
    # <family>_default, which must build and run on every target where the family has a default.
    def outcome(name: str, text: str) -> generate.Outcome:
        return generate.Outcome(written(scratch, f'{name}.outcome', text))
    every = 'targets: native wasip2 wasip3 emscripten\nbuild: succeeds\nrun: app\nok\n'
    cases = {'ed25519_default': ([], outcome('every', every))}
    page = generate.aliases_page(two_backends(), cases)
    assert ('|`+/webcpp/crypto//ed25519-default+`\n|Ed25519\n|`+/third_party//sodium+` on '
            'native; `+/third_party//bearssl+` on wasip2, wasip3, emscripten\n'
            '|<<crypto-jamfile-cases,`+ed25519_default+`>>\n') in page, page
    # One library on every target is said so.
    one = generate.aliases_page(small_table(), cases)
    assert '|`+/third_party//sodium+` on every target\n' in one, one
    # A family without a default has no row.
    data = small_table()
    data['families'][0]['default'] = [a_default(EVERY_TARGET, None)]
    assert '|`+/webcpp' not in generate.aliases_page(data, {}), generate.aliases_page(data, {})
    # An alias without its fixture, with one that fails, or with one that leaves out a target
    # where its family has a default, is a fault.
    for broken, wanted in (
            ({}, 'has no fixture ed25519_default'),
            ({'ed25519_default': ([], outcome('fails', every.replace('succeeds', 'fails')))},
             'has no fixture ed25519_default'),
            ({'ed25519_default': ([], outcome('native', every.replace(' wasip2', '')))},
             'the fixture ed25519_default does not run on wasip2')):
        try:
            generate.aliases_page(two_backends(), broken)
        except generate.Fault as fault:
            assert wanted in str(fault), fault
        else:
            raise AssertionError(f'no fault saying {wanted}')


def test_a_family_without_a_default_has_no_type(_: Path) -> None:
    data = small_table()
    data['families'][0]['default'] = [a_default(EVERY_TARGET, None)]
    header = generate.defaults_header(data)
    assert 'default_backend_of<families::ed25519>' not in header, header
    assert 'WEBCPP_CRYPTO_DETAIL_DEFAULT_ED25519' not in header, header


def test_the_default_s_refusal_says_what_the_program_needs(_: Path) -> None:
    header = generate.capabilities_header(two_backends())
    native, rest = header.split('#elif defined(WEBCPP_TARGET_WASIP2)\n', 1)
    emscripten = rest.split('#elif defined(WEBCPP_TARGET_EMSCRIPTEN)\n', 1)[1].split('#endif')[0]
    sodium = '::webcpp::crypto::backends::sodium'
    # The default, not linked: what to add, and the type that names another backend.
    assert (f'static_assert(!std::is_same_v<Backend, {sodium}> || '
            f'::webcpp::crypto::detail::linked<{sodium}>, "webcpp::crypto: Ed25519\'s default '
            'backend on this target is libsodium, which is not linked. Add '
            '/webcpp/crypto//ed25519-default, the default\'s library on every target, to the '
            'program\'s Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto '
            '/webcpp/crypto//ed25519-default ; or name another backend in the type, as in '
            'curves::ed25519::basic_keypair<backends::bearssl>. The backends that have it: '
            'sodium (native, wasip2, wasip3, emscripten), bearssl (native, wasip2, wasip3, '
            'emscripten). (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and link '
            'libsodium)")') in native, native
    # The default, linked, whose header the program did not include.
    assert (f'static_assert(!std::is_same_v<Backend, {sodium}> || '
            f'!::webcpp::crypto::detail::linked<{sodium}>, "webcpp::crypto: sodium\'s Ed25519 '
            'is in <webcpp/crypto/backends/sodium.hpp>') in native, native
    # Where no other backend has the family, there is no other type to name.
    data = small_table()
    alone = generate.capabilities_header(data).split('#elif defined(WEBCPP_TARGET_EMSCRIPTEN)\n',
                                                     1)[1]
    assert ('"webcpp::crypto: Ed25519\'s default backend on this target is libsodium, which is '
            'not linked, and the one backend that has it there. Add '
            '/webcpp/crypto//ed25519-default, the default\'s library on every target, to the '
            'program\'s Jamfile, as in: exe app : app.cpp /webcpp/crypto//crypto '
            '/webcpp/crypto//ed25519-default ; (without b2: define WEBCPP_CRYPTO_HAS_SODIUM=1 and '
            'link libsodium)")') in alone, alone
    assert 'default backend on this target is BearSSL' in emscripten, emscripten
    # Any other type is refused as no backend of the family, and nothing else is.
    assert ('static_assert(std::is_same_v<Backend, ::webcpp::crypto::backends::bearssl> || '
            f'std::is_same_v<Backend, {sodium}>, "webcpp::crypto: Ed25519 has no backend of that '
            'name.') in native, native
    assert ('template <class Backend>\ninline constexpr bool linked = false;\n'
            '#ifdef WEBCPP_CRYPTO_HAS_BEARSSL\ntemplate <>\n'
            'inline constexpr bool linked<backends::bearssl> = true;\n#endif\n') in header, header


def test_a_refusal_holds_on_its_target(_: Path) -> None:
    data = small_table()
    data['families'][0]['backends']['sodium']['targets'] = ['native']
    header = generate.capabilities_header(data)
    native, rest = header.split('#elif defined(WEBCPP_TARGET_WASIP2)\n', 1)
    wasip2 = rest.split('#elif', 1)[0]
    # Natively sodium has Ed25519: a primary engine reached means its header is not included.
    assert 'sodium\'s Ed25519 is in <webcpp/crypto/backends/sodium.hpp>' in native, native
    # On wasip2 it has none, and is never told to include a header that would not give it.
    assert ('"webcpp::crypto: sodium has no Ed25519 on wasip2. The backends that have it: sodium '
            '(native).")') in wasip2, wasip2
    assert 'is in <webcpp/crypto/backends/sodium.hpp>' not in wasip2, wasip2
    assert '#ifdef WEBCPP_CRYPTO_DETAIL_TARGET_NATIVE\n' in native, native
    assert header.count('#define WEBCPP_CRYPTO_DETAIL_REFUSE_ED25519(Backend)') == 4, header


def test_a_type_names_only_crypto_s_namespaces_from_the_root(_: Path) -> None:
    data = small_table()
    data['families'][0]['names'][0]['type'] = 'curves::ed25519::basic<std::size_t{32}, {backend}>'
    test = generate.capabilities_test(data)
    assert 'crypto::curves::ed25519::basic<std::size_t{32}, backends::sodium>' in test, test


def test_the_check_prints_each_file_that_differs(scratch: Path) -> None:
    files = {scratch / 'include/a.hpp': 'one\n', scratch / 'test/b.cpp': 'two\n'}
    generated = scratch / 'doc/generated'
    for path, text in files.items():
        written(path.parent, path.name, text)
    printed = io.StringIO()
    with redirect_stderr(printed):
        assert generate.checked(files, scratch, generated) == 0
    assert printed.getvalue() == '', printed.getvalue()
    written(scratch / 'test', 'b.cpp', 'twO\n')
    written(generated, 'old.adoc', '')
    with redirect_stderr(printed):
        assert generate.checked(files, scratch, generated) == 1
    assert printed.getvalue() == (
        'generate.py: test/b.cpp is not what crypto.json and the tree give: run python3 '
        'libs/crypto/doc/tables/generate.py\n'
        'generate.py: doc/generated/old.adoc is generated by nothing: remove it\n'), (
        printed.getvalue())


def test_the_check_names_a_file_that_differs(scratch: Path) -> None:
    files = {scratch / 'include/a.hpp': 'one\n', scratch / 'test/b.cpp': 'two\n'}
    for path, text in files.items():
        written(path.parent, path.name, text)
    assert generate.stale(files) == [], generate.stale(files)
    written(scratch / 'test', 'b.cpp', 'twO\n')
    assert generate.stale(files) == [scratch / 'test/b.cpp'], generate.stale(files)
    (scratch / 'include/a.hpp').unlink()
    assert generate.stale(files) == [scratch / 'include/a.hpp', scratch / 'test/b.cpp'], (
        generate.stale(files))


def lane_table(target: str, sizes: dict[str, int], variant: str = 'release',
               files: tuple[str, ...] = (), date: str = '2026-11-18') -> generate.Data:
    """A table the lane sizes writes (webcpp.program-sizes) on target, of the programs given with
    their bytes over the baseline, in the files given, else the target's own file."""
    kinds = files or (('executable',) if target == 'native' else ('wasm',))
    rows = [{'program': name, 'file': kind, 'bytes': 1000 + extra, 'gzip': 500 + extra // 2,
             'over_baseline': extra, 'gzip_over_baseline': extra // 2}
            for name, extra in sizes.items() for kind in kinds]
    return {'variant': variant, 'target': target, 'toolset': f'clang-{target}',
            'baseline': 'baseline', 'date': date, 'host': 'Darwin arm64',
            'format': 'Mach-O' if target == 'native' else 'WebAssembly', 'programs': rows}


def sized_table() -> generate.Data:
    """small_table's Ed25519 with the operation its lane programs measure."""
    data = small_table()
    data['families'][0]['measured'] = 'signature of a 32-byte message'
    return data


def test_the_size_matrix_reads_the_lane_s_tables(_: Path) -> None:
    sizes = generate.imported([lane_table('native', {'baseline': 0, 'ed25519_sodium': 2048}),
                               lane_table('emscripten', {'baseline': 0, 'ed25519_sodium': 4096},
                                          files=('js', 'wasm'), date='2026-11-17')])
    page = generate.sizes_page(sized_table(), sizes)
    # A cell is what its program adds to the baseline, raw and gzip -9n; on emscripten its .wasm
    # and .js together; a cell the lane has not built is not measured yet.
    assert ('|Ed25519 on libsodium: signature of a 32-byte message\n'
            '|+2,048 B, gzip +1,024 B\n'
            '|not measured yet\n'
            '|not measured yet\n'
            '|+8,192 B, gzip +4,096 B\n') in page, page
    assert ('|The baseline: the harness of every sized program, calling nothing of crypto\n'
            '|1,000 B, gzip 500 B\n'
            '|not measured yet\n'
            '|not measured yet\n'
            '|2,000 B, gzip 1,000 B\n') in page, page
    # Dated by the builds that measured it, each target with its toolset; natively the host and
    # the executable's format, which another host's native toolchain would not give.
    assert ('The lane sizes measured on 2026-11-17 to 2026-11-18, at variant=release: native, '
            'clang-native on Darwin arm64, the Mach-O executable stripped, whose segments are '
            'page-aligned: a small cell can add fewer raw bytes than its code, which its gzip -9n '
            'bytes show better; emscripten, '
            'clang-emscripten, the .wasm and its .js.') in page, page


def test_a_cell_the_backend_does_not_have_says_so(_: Path) -> None:
    data = sized_table()
    data['families'][0]['backends']['sodium'] = {'targets': ['native']}
    sizes = generate.imported([lane_table('native', {'baseline': 0, 'ed25519_sodium': 1})])
    page = generate.sizes_page(data, sizes)
    assert ('|+1 B, gzip +0 B\n'
            '|not on this target\n'
            '|not on this target\n'
            '|not on this target\n') in page, page


def a_sizes_fault(wanted: str, tables: list[generate.Data],
                  data: Optional[generate.Data] = None) -> None:
    """Checks that importing tables, or rendering them on data, is refused saying wanted."""
    try:
        generate.sizes_page(data or sized_table(), generate.imported(tables))
    except generate.Fault as fault:
        assert wanted in str(fault), fault
    else:
        raise AssertionError(f'no fault saying {wanted}')


def test_a_size_table_not_built_at_release_is_refused(_: Path) -> None:
    a_sizes_fault('a size table is built only from release builds, not variant=debug',
                  [lane_table('native', {'baseline': 0}, variant='debug')])
    a_sizes_fault('measure ed25519_sodium on native twice',
                  [lane_table('native', {'baseline': 0, 'ed25519_sodium': 1}),
                   lane_table('native', {'baseline': 0, 'ed25519_sodium': 2})])
    a_sizes_fault('measures gcm_bearssl, which is no program the lane sizes declares',
                  [lane_table('native', {'baseline': 0, 'gcm_bearssl': 1})])


def test_sizes_edited_by_hand_are_a_fault(_: Path) -> None:
    sizes = generate.imported([lane_table('native', {'baseline': 0, 'ed25519_sodium': 1})])
    sizes['tables'][0]['programs'][1]['over_baseline'] = 0
    try:
        generate.sizes_page(sized_table(), sizes)
    except generate.Fault as fault:
        assert 'doc/tables/sizes.json is not what generate.py --sizes wrote' in str(fault), fault
    else:
        raise AssertionError('a size edited by hand was taken')


def test_a_named_operation_is_a_row_under_its_cell(_: Path) -> None:
    # A family may size more operations of a cell than its fixed one: the program
    # <family>_<backend>_<operation>, whose text is the family's sized_operations entry, is a row
    # of its own after the cell's.
    data = sized_table()
    data['families'][0]['sized_operations'] = {'ph': 'Ed25519ph signature of a 32-byte message'}
    sizes = generate.imported([lane_table('native', {'baseline': 0, 'ed25519_sodium': 1,
                                                     'ed25519_sodium_ph': 7})])
    page = generate.sizes_page(data, sizes)
    assert ('|Ed25519 on libsodium: signature of a 32-byte message\n|+1 B, gzip +0 B\n'
            '|not measured yet\n|not measured yet\n|not measured yet\n\n'
            '|Ed25519 on libsodium: Ed25519ph signature of a 32-byte message\n'
            '|+7 B, gzip +3 B\n') in page, page


def test_what_the_size_matrix_cannot_read_is_a_fault(_: Path) -> None:
    # A program of no name form, a family without its measured operation and a table of no
    # program are faults that say what to write, never a KeyError or an IndexError.
    a_sizes_fault('measures ed25519_sodium_other, which is no program the lane sizes declares: '
                  'its programs are baseline, <family>_<backend> for a cell of crypto.json\'s '
                  'families, and <family>_<backend>_<operation> for an operation of the '
                  'family\'s sized_operations',
                  [lane_table('native', {'baseline': 0, 'ed25519_sodium_other': 1})])
    data = sized_table()
    del data['families'][0]['measured']
    a_sizes_fault('crypto.json: the family ed25519 has no measured, the text of the fixed '
                  'operation its sized programs call', [lane_table('native', {'baseline': 0})],
                  data)
    empty = lane_table('native', {})
    a_sizes_fault('a table of the lane sizes on native holds no program', [empty])
    undated = lane_table('native', {'baseline': 0})
    del undated['date']
    a_sizes_fault('a table of the lane sizes lacks date: run the lane again', [undated])


def test_a_backend_s_size_note_is_written_under_the_table(_: Path) -> None:
    data = sized_table()
    data['backends']['sodium']['size_note'] = 'libsodium is one library.'
    page = generate.sizes_page(data, generate.imported([lane_table('native', {'baseline': 0})]))
    assert page.endswith('|===\n\nlibsodium: libsodium is one library.\n'), page


def test_a_family_s_measured_constant_time_is_written_per_target(_: Path) -> None:
    data = small_table()
    data['families'][0]['backends']['sodium']['constant_time'] = {
        'wasip2': 'measured over the threshold ({rfc8032})'}
    notes = generate.constant_time_notes(data)
    assert notes == ('\nMeasured where a family differs from its backend\'s design:\n\n'
                     '* Ed25519 on libsodium, wasip2: measured over the threshold '
                     '(link:https://example.org[RFC 8032])\n'), notes
    assert generate.constant_time_notes(small_table()) == '', 'no entry, no list'


def two_ciphers() -> generate.Data:
    """A comparison table of two ciphers with D19's columns, the world's facts cited."""
    return {
        'sources': {'rfc8439': ['RFC 8439', 'https://example.org/rfc8439'],
                    'wireguard': ['WireGuard', 'https://example.org/wireguard']},
        'namespaces': {'ciphers': {
            'title': 'webcpp::crypto::ciphers',
            'columns': ['Algorithm', 'AEAD', 'Key', 'Nonce (IV)', 'Nonce misuse',
                        'Speed, with and without hardware support',
                        'Constant time, by design', 'Constant time, measured', 'Standards',
                        'Where it is used', "Browsers' WebCrypto", 'Choose it when'],
            'cited': ['Standards', 'Where it is used'],
            'rows': [['`chacha20_poly1305`: ChaCha20-Poly1305', 'yes', '32 bytes', '12 bytes',
                      'not resistant', '{speed:chacha20_poly1305}', 'yes',
                      '{constant_time:chacha20_poly1305}', '{rfc8439}',
                      'WireGuard ({wireguard})', 'no', 'a protocol names it'],
                     ['`aes256`: AES block cipher', 'no', '32 bytes', 'none',
                      'not applicable', 'not measured yet', 'yes', 'not measured yet',
                      '{rfc8439}', 'none on its own: every mode is built on it', 'no',
                      'one block']]}},
        'families': [{'name': 'chacha20_poly1305', 'title': 'ChaCha20-Poly1305',
                      'backends': {
                          'sodium': {'targets': 'all',
                                     'lane': {'native': ['memcheck', 'dudect'],
                                              'wasip2': ['dudect']},
                                     'constant_time': {
                                         'wasip2': 'over the threshold ({rfc8439})'}},
                          'bearssl': {'targets': 'all'}}}],
        'checkers': {'memcheck': 'memcheck (Linux)', 'dudect': 'dudect'},
        'backends': {'sodium': {'title': 'libsodium', 'targets': EVERY_TARGET},
                     'bearssl': {'title': 'BearSSL', 'targets': EVERY_TARGET}},
        'targets': EVERY_TARGET}


def measured(median: float, load: float = 1.0) -> generate.Data:
    """doc/performance.json's form, one case: ChaCha20-Poly1305 on libsodium, natively, on a
    machine of 18 cores whose 1-minute load was `load`."""
    return {'date': '2026-11-18', 'build': 'variant=release',
            'machine': {'cpu': 'Apple M5 Max', 'cores': 18},
            'load_average_before_after': [[load, 1.0, 1.0], [1.0, 1.0, 1.0]], 'cases': [
                {'family': 'chacha20_poly1305', 'backend': 'sodium', 'target': 'native',
                 'operation': 'seal of 16 KiB, 256-bit key', 'median_us': median}]}


def test_the_ciphers_table_has_the_columns_of_d19(_: Path) -> None:
    page = generate.namespace_page(two_ciphers(), 'ciphers', measured(22.5))
    for question in ('AEAD', 'Key', 'Nonce (IV)', 'Nonce misuse',
                     'Speed, with and without hardware support', 'Constant time, by design',
                     'Constant time, measured', 'Standards', 'Where it is used',
                     "Browsers' WebCrypto", 'Choose it when'):
        assert f'\n|{question}\n' in page, (question, page)
    # The speed is the measurement's, never typed: per target, each backend's median to three
    # significant figures, dated.
    assert ('|seal of 16 KiB, 256-bit key: native, libsodium 22.5 µs (2026-11-18, Apple M5 Max; '
            '<<crypto-performance>>)\n') in page, page
    # The measured constant time is what the lane covers, per backend and target, with the
    # family's finding where it has one, and not measured yet elsewhere.
    assert ('|libsodium: native, memcheck (Linux) and dudect, nothing found; wasip2, dudect: '
            'over the threshold (link:https://example.org/rfc8439[RFC 8439]); not measured yet '
            'on wasip3, emscripten. BearSSL: not measured yet '
            '(<<crypto-backends-constant-time>>)\n') in page, page
    # A machine loaded beyond half its cores is said so beside the figure.
    loaded = generate.namespace_page(two_ciphers(), 'ciphers', measured(22.5, load=89.6))
    assert '(2026-11-18, Apple M5 Max, under load: read the spread; <<crypto-performance>>)' in (
        loaded), loaded
    try:
        data = two_ciphers()
        data['namespaces']['ciphers']['rows'][0][5] = '{speed:aegis}'
        generate.namespace_page(data, 'ciphers', measured(22.5))
    except generate.Fault as fault:
        assert 'names the family aegis' in str(fault), fault
    else:
        raise AssertionError('a measurement of a family crypto.json does not list was written')


def test_a_world_fact_without_a_source_is_refused_naming_the_row(_: Path) -> None:
    data = two_ciphers()
    data['namespaces']['ciphers']['rows'][0][9] = 'WireGuard'
    try:
        generate.namespace_page(data, 'ciphers', measured(22.5))
    except generate.Fault as fault:
        assert str(fault) == ('crypto.json: the ciphers table\'s row `chacha20_poly1305`: '
                              'ChaCha20-Poly1305 states "Where it is used" without a source: '
                              'cite one, {<source>}, or begin it with "none"'), fault
    else:
        raise AssertionError('a world fact without a source was written')


def test_the_check_fails_after_a_measurement_changes(_: Path) -> None:
    before = generate.namespace_page(two_ciphers(), 'ciphers', measured(22.5))
    after = generate.namespace_page(two_ciphers(), 'ciphers', measured(23.0))
    assert before != after and 'libsodium 23 µs' in after, after


def test_the_decision_table_s_row_links_its_example(scratch: Path) -> None:
    written(scratch, 'example/xchacha_seal.cpp', '')
    entry = {'need': 'encrypt messages in a chat app', 'namespace': 'webcpp::crypto::ciphers',
             'api': '`xchacha20_poly1305`', 'backend': 'libsodium',
             'jamfile': '/webcpp/crypto//crypto', 'example': 'xchacha_seal',
             'section': 'crypto-chacha'}
    page = generate.use_cases_page({'use_cases': [entry]}, scratch)
    assert '\n|<<crypto-chacha,[.keep]`+xchacha_seal.cpp+`>>\n' in page, page
    try:
        generate.use_cases_page({'use_cases': [dict(entry, example='')]}, scratch)
    except generate.Fault as fault:
        assert str(fault) == ('crypto.json: the use case "encrypt messages in a chat app" names '
                              'no example: each row a program can follow links one'), fault
    else:
        raise AssertionError('a row without an example was written')
    # A row of what this version does not offer links none.
    page = generate.use_cases_page({'use_cases': [dict(entry, example='', jamfile='none')]},
                                   scratch)
    assert '\n|<<crypto-chacha>>\n' in page, page


def test_llms_lists_a_function_with_its_use_case_and_backends(scratch: Path) -> None:
    written(scratch, 'include/webcpp/crypto/ciphers/x.hpp',
            '/** Seals data in place. */\nint seal(int);\n')
    data = small_table()
    data.update({'page': 'https://example.org/crypto.html', 'rules': [], 'llms': 'Summary.',
                 'namespaces': {'ciphers': {'title': 'webcpp::crypto::ciphers'}}})
    data['operations'] = [{'id': 'seal', 'family': 'ed25519', 'namespace': 'ciphers',
                           'api': 'ciphers::x', 'functions': ['seal'],
                           'header': '<webcpp/crypto/ciphers/x.hpp>', 'what': 'Seals.',
                           'section': 'crypto-x', 'backends': {'sodium': {'tests': ['t']}}}]
    data['families'][0]['backends']['sodium']['constant_time'] = {'wasip2': 'an open finding'}
    data['families'][0]['backends']['sodium']['lane'] = {'wasip2': ['dudect']}
    data['checkers'] = {'dudect': 'dudect'}
    data['use_cases'] = [{'need': 'encrypt a chat message', 'namespace': 'webcpp::crypto::ciphers',
                          'api': '`x`', 'backend': 'libsodium', 'jamfile': 'j', 'example': '',
                          'section': 'crypto-x'}]
    matrix = generate.Matrix(data, {'t': ['native', 'wasip2']}, {})
    text = generate.llms(data, matrix, scratch)
    assert text.startswith('# webcpp::crypto\n\n> Summary.\n'), text
    assert ('- [ciphers::x](https://example.org/crypto.html#crypto-x): Seals. Header '
            '<webcpp/crypto/ciphers/x.hpp>. Backends: libsodium (/third_party//sodium) on '
            'native, wasip2. Default: libsodium on native, wasip2, wasip3, emscripten. Use it '
            'to: encrypt a chat message.\n  - seal: Seals data in place.\n') in text, text
    assert ('## Constant time, measured\n\n- Ed25519: libsodium: wasip2, dudect: an open '
            'finding; not measured yet on native, wasip3, emscripten.\n') in text, text


def test_every_backend_s_facts_and_design_are_written_with_its_own_suite(_: Path) -> None:
    data = small_table()
    for name in ('bearssl', 'sodium'):
        data['backends'][name].update({
            'library': f"{data['backends'][name]['title']} 1.0", 'licence': 'ISC',
            'own_api': '`<x.h>`',
            'allocation': 'none ({rfc8032})', 'constant_time': 'by design ({rfc8032})',
            'constant_time_sources': []})
    data['backends']['sodium']['own_suite'] = {
        'lane': "webcpp::hash's own lane `c-suites`", 'programs': ['sign', 'box']}
    matrix = generate.Matrix(data, {'ed25519': EVERY_TARGET}, {})
    facts = generate.facts_page(data, matrix)
    assert '\n|libsodium\n|libsodium 1.0\n|ISC\n' in facts, facts
    # A fact of a backend's cites its source as the tables' facts do.
    assert '|none (link:https://example.org[RFC 8032])\n' in facts, facts
    assert ('libsodium\'s own test suite runs in webcpp::hash\'s own lane `+c-suites+`: '
            '`+sign+`, `+box+`.\n') in facts, facts
    page = generate.constant_time_page(data)
    assert '\n|libsodium\n|by design (link:https://example.org[RFC 8032])\n' in page, page
    # The system's generator, with no library of its own, has no row.
    assert 'The system' not in facts and 'The system' not in page, (facts, page)


def test_the_namespaces_and_backends_come_from_the_data(_: Path) -> None:
    data = {'namespaces': {'pq': {'title': 'webcpp::crypto::post_quantum'}},
            'backends': {'zeta': {}, 'alpha': {}}}
    assert generate.namespace_titles(data) == {'pq': 'webcpp::crypto::post_quantum'}
    assert generate.backend_order(data) == ['zeta', 'alpha'], generate.backend_order(data)


def test_every_api_page_lists_its_default_per_target(_: Path) -> None:
    data = small_table()
    data['operations'][0].update({'api': 'curves::ed25519::sign'})
    matrix = generate.Matrix(data, {'ed25519': EVERY_TARGET}, {})
    page = generate.api_backends(data, matrix, data['operations'][0])
    assert ('A call that names no backend takes the family\'s default on each target, '
            'whatever the program links, as <<crypto-backends-defaults>> gives it with its '
            'reasons and tests:\n') in page, page
    assert '|native, wasip2, wasip3, emscripten\n|libsodium\n' in page, page


def test_a_use_case_joins_the_operation_it_names(_: Path) -> None:
    data = {'use_cases': [
        {'need': 'Encrypt chat messages', 'api': '`xchacha20_poly1305<>`', 'section': 's'},
        {'need': 'Speak TLS 1.3', 'api': '`chacha20_poly1305<>`', 'section': 's'}]}
    assert generate.llms_uses(data, {'api': 'ciphers::chacha20_poly1305', 'section': 's'}) == (
        ' Use it to: speak TLS 1.3.')
    assert generate.llms_uses(data, {'api': 'ciphers::xchacha20_poly1305', 'section': 's'}) == (
        ' Use it to: encrypt chat messages.')


def test_a_measurement_not_built_at_release_is_refused(scratch: Path) -> None:
    import json
    written(scratch, 'doc/performance.json', json.dumps(measured(22.5)))
    assert generate.read_performance(scratch)['cases'], 'the measurement was not read'
    written(scratch, 'doc/performance.json', json.dumps(dict(measured(22.5), build='debug')))
    try:
        generate.read_performance(scratch)
    except generate.Fault as fault:
        assert str(fault) == ('doc/performance.json was built at debug, not variant=release: '
                              'measure again with bench/collect.py'), fault
    else:
        raise AssertionError('a measurement not built at release was read')


def test_a_speed_cell_names_each_operation_and_refuses_an_unknown_backend(_: Path) -> None:
    performance = measured(22.5)
    performance['cases'].append(dict(performance['cases'][0], operation='open of 16 KiB',
                                     median_us=0.012345))
    cell = generate.speed_of(two_ciphers(), 'chacha20_poly1305', performance)
    assert cell == ('seal of 16 KiB, 256-bit key: native, libsodium 22.5 µs; open of 16 KiB: '
                    'native, libsodium 0.0123 µs (2026-11-18, Apple M5 Max; '
                    '<<crypto-performance>>)'), cell
    performance['cases'][0]['backend'] = 'aegis_lib'
    try:
        generate.speed_of(two_ciphers(), 'chacha20_poly1305', performance)
    except generate.Fault as fault:
        assert 'names the backend aegis_lib' in str(fault), fault
    else:
        raise AssertionError('a measurement of an unknown backend was written')


def test_the_constant_time_page_fills_each_target_from_the_lane(_: Path) -> None:
    data = two_ciphers()
    for backend in data['backends'].values():
        backend.update({'library': 'l', 'constant_time': 'by design', 'constant_time_sources': []})
    data['backends']['none'] = {'title': 'no backend', 'library': 'own', 'constant_time': 'yes',
                                'constant_time_sources': [], 'lane_paths': [
                                    {'what': '`equal`', 'lane': {'native': ['memcheck']}}]}
    page = generate.constant_time_page(data)
    assert ('|libsodium\n|by design\n|memcheck (Linux): ChaCha20-Poly1305; dudect: '
            'ChaCha20-Poly1305\n|dudect: ChaCha20-Poly1305 (measured differently, below)\n'
            '|not measured yet\n|not measured yet\n') in page, page
    assert '|no backend\n|yes\n|memcheck (Linux): `+equal+`\n|not measured yet\n' in page, page


def test_a_note_on_one_family_of_a_cell_names_that_family(_: Path) -> None:
    data = two_ciphers()
    for backend in data['backends'].values():
        backend.update({'library': 'l', 'constant_time': 'by design', 'constant_time_sources': []})
    data['families'].insert(0, {'name': 'ed25519', 'title': 'Ed25519', 'backends': {
        'sodium': {'targets': 'all', 'lane': {'wasip2': ['dudect']}}}})
    page = generate.constant_time_page(data)
    assert ('|dudect: Ed25519, ChaCha20-Poly1305 (ChaCha20-Poly1305 measured differently, '
            'below)\n') in page, page


def test_a_lane_note_of_one_checker_is_written_beside_that_checker_alone(_: Path) -> None:
    data = two_ciphers()
    for backend in data['backends'].values():
        backend.update({'library': 'l', 'constant_time': 'by design', 'constant_time_sources': []})
    entry = data['families'][0]['backends']['sodium']
    del entry['constant_time']
    entry['lane_note'] = {'dudect': 'seal alone'}
    page = generate.constant_time_page(data)
    assert ('|libsodium\n|by design\n|memcheck (Linux): ChaCha20-Poly1305; dudect: '
            'ChaCha20-Poly1305 (seal alone)\n|dudect: ChaCha20-Poly1305 (seal alone)\n'
            ) in page, page
    text = generate.lane_text(data, data['families'][0], generate.cite)
    assert text.startswith('libsodium: native, memcheck (Linux) and dudect (seal alone), nothing '
                           'found; wasip2, dudect (seal alone), nothing found'), text
    # A checker whose name ends in its own parenthesis takes the note inside it.
    entry['lane_note'] = {'memcheck': 'seal alone'}
    text = generate.lane_text(data, data['families'][0], generate.cite)
    assert text.startswith('libsodium: native, memcheck (Linux; seal alone) and dudect, nothing '
                           'found; wasip2, dudect, nothing found'), text
    # A note of every checker stays beside the backend's name.
    entry['lane_note'] = 'its own tests'
    text = generate.lane_text(data, data['families'][0], generate.cite)
    assert text.startswith('libsodium (its own tests): native, memcheck (Linux) and dudect'), text


def test_a_lane_note_of_a_checker_the_lane_does_not_run_is_a_fault(_: Path) -> None:
    data = small_table()
    data['checkers'] = {'memcheck': 'memcheck (Linux)', 'dudect': 'dudect'}
    entry = data['families'][0]['backends']['sodium']
    entry['lane'] = {'native': ['memcheck']}
    entry['lane_note'] = {'dudect': 'seal alone'}
    a_fault(data, {'ed25519': EVERY_TARGET},
            'gives sodium a lane note for dudect, which its lane does not run')
    entry['lane_note'] = {'msan': 'seal alone'}
    a_fault(data, {'ed25519': EVERY_TARGET},
            'gives sodium a lane note for msan, which its lane does not run')


def test_a_lane_entry_the_family_does_not_claim_is_a_fault(_: Path) -> None:
    data = small_table()
    data['checkers'] = {'dudect': 'dudect'}
    entry = data['families'][0]['backends']['sodium']
    entry['lane'] = {'wasip2': ['valgrind']}
    a_fault(data, {'ed25519': EVERY_TARGET}, 'names the checker valgrind')
    entry['lane'] = {'native': ['dudect']}
    entry['constant_time'] = {'wasip2': 'a finding'}
    a_fault(data, {'ed25519': EVERY_TARGET},
            'states constant time for sodium on wasip2, where the lane does not run it')


def test_llms_gives_no_default_where_the_family_has_none(_: Path) -> None:
    data = small_table()
    data['families'][0]['default'] = [{'targets': EVERY_TARGET, 'backend': None, 'tests': [],
                                       'why': 'none'}]
    operation = {'family': 'ed25519', 'default_of': 'ed25519',
                 'default': '`x<>` names AES-GCM\'s default.'}
    assert generate.llms_default(data, operation) == (
        ' Default: none on native, wasip2, wasip3, emscripten; `x<>` names AES-GCM\'s default.')


def test_a_namespace_table_is_split_into_its_parts(_: Path) -> None:
    data = two_ciphers()
    data['namespaces']['ciphers']['parts'] = [{'title': 'ChaCha', 'rows': [0]},
                                              {'title': 'AES', 'rows': [1]}]
    page = generate.namespace_page(data, 'ciphers', measured(22.5))
    assert page.startswith('.ChaCha\n[cols="2h,5",options="header"]\n|===\n'
                           '|Algorithm |ChaCha20-Poly1305\n'), page
    assert '\n.AES\n[cols="2h,5",options="header"]\n|===\n|Algorithm |AES block cipher\n' in (
        page), page
    data['namespaces']['ciphers']['parts'] = [{'title': 'ChaCha', 'rows': [0]}]
    try:
        generate.namespace_page(data, 'ciphers', measured(22.5))
    except generate.Fault as fault:
        assert str(fault) == ("crypto.json: the ciphers table's parts hold its rows 0 once each, "
                              'not 0 to 1'), fault
    else:
        raise AssertionError('a row left out of every part was written')

CASES: list[Callable[[Path], None]] = [
    test_a_rule_body_declares_nothing,
    test_a_program_inside_an_if_is_a_fault,
    test_the_memory_option_s_tests_are_declared,
    test_a_backend_says_why_it_is_missing_elsewhere,
    test_a_reason_elsewhere_is_openssl_s_alone,
    test_an_outcome_reads_each_directive,
    test_a_brief_leaves_out_a_line_reference,
    test_a_qualified_function_is_read_in_its_class,
    test_an_index_entry_names_a_qualified_function_bare,
    test_the_edge_cases_table_has_a_row_per_case_and_a_column_per_verdict,
    test_an_edge_cases_key_the_generator_does_not_know_is_a_fault,
    test_code_that_holds_a_plus_is_one_span,
    test_a_failing_fixture_lists_its_texts_per_target,
    test_a_fixture_that_builds_and_runs_nothing_is_a_record,
    test_a_comparison_column_is_headed_by_its_plain_name,
    test_the_decision_table_writes_no_jamfile_as_prose,
    test_a_backend_without_a_family_is_refused_naming_those_that_have_it,
    test_a_cell_decided_at_run_time_says_so,
    test_each_cell_is_true_on_its_targets_alone,
    test_the_generated_test_asserts_every_cell,
    test_a_family_that_names_an_unknown_backend_is_a_fault,
    test_a_cell_claimed_where_no_test_runs_is_a_fault,
    test_a_default_is_a_backend_of_the_family_its_tests_run_on,
    test_the_defaults_header_chooses_by_the_target_alone,
    test_a_row_of_some_compilers_is_labelled_with_their_names,
    test_the_other_backend_a_refusal_names_is_chosen_as_stated,
    test_a_family_without_a_default_has_no_type,
    test_each_family_s_default_has_an_alias_that_links_it_per_target,
    test_each_alias_has_a_row_and_a_fixture_that_runs_it_where_its_family_has_a_default,
    test_the_default_s_refusal_says_what_the_program_needs,
    test_a_refusal_holds_on_its_target,
    test_a_type_names_only_crypto_s_namespaces_from_the_root,
    test_the_check_prints_each_file_that_differs,
    test_the_check_names_a_file_that_differs,
    test_the_size_matrix_reads_the_lane_s_tables,
    test_a_cell_the_backend_does_not_have_says_so,
    test_a_size_table_not_built_at_release_is_refused,
    test_sizes_edited_by_hand_are_a_fault,
    test_a_named_operation_is_a_row_under_its_cell,
    test_what_the_size_matrix_cannot_read_is_a_fault,
    test_a_backend_s_size_note_is_written_under_the_table,
    test_a_family_s_measured_constant_time_is_written_per_target,
    test_the_ciphers_table_has_the_columns_of_d19,
    test_a_world_fact_without_a_source_is_refused_naming_the_row,
    test_the_check_fails_after_a_measurement_changes,
    test_the_decision_table_s_row_links_its_example,
    test_llms_lists_a_function_with_its_use_case_and_backends,
    test_every_backend_s_facts_and_design_are_written_with_its_own_suite,
    test_the_namespaces_and_backends_come_from_the_data,
    test_every_api_page_lists_its_default_per_target,
    test_a_use_case_joins_the_operation_it_names,
    test_a_measurement_not_built_at_release_is_refused,
    test_a_speed_cell_names_each_operation_and_refuses_an_unknown_backend,
    test_the_constant_time_page_fills_each_target_from_the_lane,
    test_a_note_on_one_family_of_a_cell_names_that_family,
    test_a_lane_entry_the_family_does_not_claim_is_a_fault,
    test_a_lane_note_of_one_checker_is_written_beside_that_checker_alone,
    test_a_lane_note_of_a_checker_the_lane_does_not_run_is_a_fault,
    test_llms_gives_no_default_where_the_family_has_none,
    test_a_namespace_table_is_split_into_its_parts,
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
