#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Measures bench/throughput.cpp on each target and bench/timing.cpp natively, and renders their
data, after webcpp::hash's.

    collect.py --exe native=<path> --exe wasip2=<path> ... --invocations 5 \\
        --timing <path> \\
        --data libs/crypto/doc/performance.json --page libs/crypto/doc/performance.adoc

Run from the superproject's root (the launchers' paths, tools/boost/asio-wasip2/run.sh and its
wasip3 twin, are relative to it), with the programs bench/Jamfile builds at variant=release,
`b2 libs/crypto/bench//throughput` on each target and `b2 libs/crypto/bench//timing` natively;
--data and --page are relative to the same root. `--timing` alone, without `--exe`, measures the
guard again and keeps the data's throughput.

The page is built only from release builds: a program whose build directory, b2's
bench/<toolset>/<variant>/..., is not variant=release, or does not say, is refused before anything
runs, and `--render-only` refuses data whose build, or whose guard's build, is not BUILD.

Each cell (a family on a backend, on a target) is run INVOCATIONS times, round-robin over the
cells so that a change of load on a shared machine falls on all of them alike; each invocation
times five runs of the family's fixed operation and reports their median, in microseconds per
operation. The data holds, per cell, every invocation's median, their median, and the fastest and
slowest single run. The operation each cell's program reports must be the one
doc/tables/crypto.json states for its family (the size matrix's), or the cell is refused. A cell
the program lists with a third word, `<family> <backend> <operation>`, is a further operation of
the family, measured as `throughput <family> <backend> <operation>`, whose text is the entry of
that name in the family's "sized_operations". A time
never fails this script: only a program that does not run, or a cell it does not know, does.
`--render-only` rewrites the page from the data.

`--provisional` marks figures as provisional, measured on a shared, loaded machine and to be
measured again in a final pass on a quiet one. Each part has its own mark: the throughput's is the
data's `"provisional": true`, the guard's is `"provisional": true` in its "timing_guard", and each
table's NOTE renders from its own. A measurement marks, with `--provisional`, or clears, without
it, the mark of the part it measured alone (`--exe` the throughput's, `--timing` the guard's), and
keeps the other part's as it was. With `--render-only` it marks both parts the data holds, numbers
unchanged.

Data that is not what this script writes (not a JSON object, a key missing or of another type, a
family, backend or target the page does not know), and a program's line that is not the form this
script reads (an older bench/timing.cpp's, without the fastest and slowest runs, among them), are
refused with a message naming what is wrong, before the page is written.

The timing guard's cost (detail::timing_guard, which every public operation holds and which sets
64-bit ARM's DIT where the CPU has it) is `timing --measure`'s one line: whether the guard sets DIT
on this machine, and the nanoseconds a guard adds to a call entered from a thread whose DIT is
clear and from one where it is already set, each the median of five runs of 10^7 guards minus an
empty loop's, with the fastest and slowest run. The data keeps it under "timing_guard" with the
date, the machine and the load; the page renders it as a paragraph and a two-row table under the
throughput. Every date is UTC's, as the constant-time lane's are.

libsodium's x86-64 assembly (HAVE_AMD64_ASM, design D7) is recorded beside the table as not
measured yet, with its reason, until an x86-64 machine runs a scratch build of it by hand.
"""

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

# What the page is built from, and only from: bench/Jamfile's throughput, at variant=release.
BUILD = "variant=release"
RELEASE_ONLY = (
    "the page is built only from release builds: bench/Jamfile's throughput at " + BUILD
)

LAUNCHERS = {
    "native": [],
    "wasip2": ["tools/boost/asio-wasip2/run.sh"],
    "wasip3": ["tools/boost/asio-wasip3/run.sh"],
    "emscripten": ["node"],
}
TARGETS = ["native", "wasip2", "wasip3", "emscripten"]
CRYPTO_JSON = Path(__file__).resolve().parent.parent / "doc/tables/crypto.json"
# Design D7's libsodium x86-64 assembly: the rows the page records, and why they are not measured.
AMD64_ASM = {
    "rows": ["Ed25519 signature, libsodium with HAVE_AMD64_ASM",
             "X25519 agreement, libsodium with HAVE_AMD64_ASM"],
    "status": "not measured yet",
    "reason": "x86-64 assembly runs only on an x86-64 machine; this page's machine is arm64. "
              "D7 asks for the rows recorded, never used: webcpp builds libsodium without it.",
}


def variant_of(exe):
    """The variant b2 built exe at, as its build directory names it, bench/<toolset>/<variant>/...;
    None when its path does not say."""
    parts = Path(exe).resolve().parts
    if "bench" not in parts:
        return None
    last = len(parts) - 1 - parts[::-1].index("bench")
    after = parts[last + 1:]
    return after[1] if len(after) > 2 else None


def check_release(exes):
    """Exits naming each program not built at variant=release, before anything runs; exes maps
    a target, or "timing" for the guard's program, to its path."""
    others = []
    for target, exe in exes.items():
        variant = variant_of(exe)
        if variant is None:
            others.append(f"{target}={exe} is not in b2's bench/<toolset>/<variant>/..., so its "
                          "variant cannot be read")
        elif variant != "release":
            others.append(f"{target}={exe} was built at variant={variant}")
    if others:
        sys.exit("collect.py: " + ", ".join(others) + ": " + RELEASE_ONLY)


def crypto_json():
    with open(CRYPTO_JSON, encoding="utf-8") as f:
        return json.load(f)


def utc_today():
    """Today's date in UTC, the date every measurement of crypto's states."""
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def median(values):
    values = sorted(values)
    n = len(values)
    return values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2


def tool_version(command):
    try:
        out = subprocess.run(command, capture_output=True, text=True, check=False)
        return (out.stdout or out.stderr).strip().splitlines()[0]
    except (OSError, IndexError):
        return "unknown"


def sysctl(name):
    try:
        out = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, check=False)
        return out.stdout.strip()
    except OSError:
        return ""


def machine():
    return {
        "cpu": sysctl("machdep.cpu.brand_string") or platform.processor() or platform.machine(),
        "architecture": platform.machine(),
        "cores": os.cpu_count(),
        "memory_gib": int(sysctl("hw.memsize") or 0) // 2**30,
        "os": f"{platform.system()} {platform.release()}",
        "wasmtime": tool_version(["wasmtime", "--version"]),
        "node": tool_version(["node", "--version"]),
    }


# The shapes of the data and of the programs' lines: a key's type, the shape of a nested object, a
# one-element list for a list of that shape, or a function that says whether a value is right. A
# key of OPTIONAL may be missing.
NUMBER = (int, float)


def load_pair(value):
    """Whether value is the load averages before and after: two lists of numbers, neither empty."""
    return (isinstance(value, list) and len(value) == 2 and
            all(isinstance(loads, list) and loads and
                all(isinstance(x, NUMBER) and not isinstance(x, bool) for x in loads)
                for loads in value))


MACHINE_SHAPE = {"cpu": str, "architecture": str, "cores": (int, type(None)),
                 "memory_gib": int, "os": str, "wasmtime": str, "node": str}
CASE_SHAPE = {"family": str, "backend": str, "target": str, "operation": str, "compiler": str,
              "median_us": NUMBER, "min_us": NUMBER, "max_us": NUMBER}
DATA_SHAPE = {"date": str, "machine": MACHINE_SHAPE, "load_average_before_after": load_pair,
              "build": str, "cases": [CASE_SHAPE],
              "amd64_asm": {"rows": [str], "status": str, "reason": str}}
TIMING_SHAPE = {"date": str, "machine": MACHINE_SHAPE, "load_average_before_after": load_pair,
                "build": str, "target": str, "compiler": str, "iterations": int, "runs": int,
                "dit": bool, "clear_ns": NUMBER, "set_ns": NUMBER}
# Recorded since the guard's spread was: data measured before it lacks them, and the page says
# "not recorded".
TIMING_OPTIONAL = {"clear_fastest_ns": NUMBER, "clear_slowest_ns": NUMBER,
                   "set_fastest_ns": NUMBER, "set_slowest_ns": NUMBER, "provisional": bool}
# bench/timing.cpp's line, every key since the guard's spread is recorded.
TIMING_LINE_SHAPE = {"target": str, "compiler": str, "iterations": int, "runs": int, "dit": bool,
                     "clear": NUMBER, "clear_fastest": NUMBER, "clear_slowest": NUMBER,
                     "set": NUMBER, "set_fastest": NUMBER, "set_slowest": NUMBER}
# bench/throughput.cpp's line.
THROUGHPUT_LINE_SHAPE = {"operation": str, "compiler": str, "repetitions": int,
                         "median_us": NUMBER, "runs_us": [NUMBER]}


def wrong(value, shape, where, optional=None):
    """The first place in value that shape requires and value lacks or holds otherwise, named as
    a path from where; None when value has the shape."""
    if callable(shape) and not isinstance(shape, type):
        return None if shape(value) else where
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            return f"{where} (not an object)"
        for key, inner in shape.items():
            if key not in value:
                return f"{where}.{key} (missing)"
            found = wrong(value[key], inner, f"{where}.{key}")
            if found is not None:
                return found
        for key, inner in (optional or {}).items():
            if key in value and value[key] is not None:
                found = wrong(value[key], inner, f"{where}.{key}")
                if found is not None:
                    return found
        return None
    if isinstance(shape, list):
        if not isinstance(value, list) or not value:
            return f"{where} (not a list, or empty)"
        for index, item in enumerate(value):
            found = wrong(item, shape[0], f"{where}[{index}]")
            if found is not None:
                return found
        return None
    types = shape if isinstance(shape, tuple) else (shape,)
    if isinstance(value, bool) and bool not in types:
        return where
    return None if isinstance(value, types) else where


def program_line(target, command, output, shape):
    """The last line of a program's output, read as JSON of shape; exits naming the program and
    what is wrong when it is not."""
    lines = output.strip().splitlines()
    try:
        line = json.loads(lines[-1]) if lines else None
    except ValueError as error:
        sys.exit(f"collect.py: {target} {' '.join(command)} printed a line that is not JSON "
                 f"({error}): {lines[-1]!r}")
    found = wrong(line, shape, "line")
    # Each shape is an object's, so wrong finds nothing only in a dict; the isinstance states
    # that to the type checker, and the line comes back a dict, never None.
    if found is None and isinstance(line, dict):
        return line
    printed = lines[-1] if lines else ""
    sys.exit(f"collect.py: {target} {' '.join(command)} printed {printed!r}, which is not "
             f"the form collect.py reads: {found or 'line (not an object)'} is wrong; build "
             "bench/Jamfile's program again from this tree")


def run(target, command):
    done = subprocess.run(LAUNCHERS[target] + command, capture_output=True, text=True,
                          check=False)
    if done.returncode != 0:
        sys.exit(f"{target} {' '.join(command[1:])}: exit {done.returncode}\n"
                 f"{done.stdout}{done.stderr}")
    return done.stdout


def cells_of(target, exe, families):
    """The cells the program was built with, which it lists without measuring, each as (family,
    backend, operation), the operation "" for the family's fixed one; each must be a family of
    crypto.json, and a further operation one of its "sized_operations"."""
    cells = []
    for line in run(target, [exe, "--list"]).splitlines():
        words = line.split()
        if not words:
            continue
        if len(words) not in (2, 3):
            sys.exit(f"collect.py: {target} lists {line!r}, which is not "
                     "\"<family> <backend> [<operation>]\"")
        family, backend = words[0], words[1]
        further = words[2] if len(words) == 3 else ""
        if family not in families:
            sys.exit(f"collect.py: {target} lists {family} {backend}, and crypto.json has no "
                     f"family {family}")
        if further and further not in families[family].get("sized_operations", {}):
            sys.exit(f"collect.py: {target} lists {family} {backend} {further}, and crypto.json's "
                     f"family {family} has no sized operation {further}")
        cells.append((family, backend, further))
    return cells


def stated_operation(family, further):
    """The operation crypto.json states for a cell: the family's fixed one, or the further one of
    that name."""
    return family["sized_operations"][further] if further else family["measured"]


def measure(exes, invocations):
    data = crypto_json()
    families = {family["name"]: family for family in data["families"]}
    cases = {}
    for target, exe in exes.items():
        for family, backend, further in cells_of(target, exe, families):
            cases[(target, family, backend, further)] = {"exe": exe, "results": []}
    loads = [os.getloadavg()]
    for _ in range(invocations):
        for (target, family, backend, further), case in cases.items():
            command = [case["exe"], family, backend] + ([further] if further else []) + [
                "--runs", "5"]
            case["results"].append(program_line(target, command, run(target, command),
                                                THROUGHPUT_LINE_SHAPE))
    loads.append(os.getloadavg())
    out = []
    for (target, family, backend, further), case in cases.items():
        results = case["results"]
        stated = stated_operation(families[family], further)
        if results[0]["operation"] != stated:
            sys.exit(f"collect.py: {target} {family} {backend}{' ' + further if further else ''} "
                     f"measures {results[0]['operation']!r}, and crypto.json states {stated!r}")
        medians = [r["median_us"] for r in results]
        runs = [t for r in results for t in r["runs_us"]]
        out.append({
            "family": family,
            "backend": backend,
            "target": target,
            "operation": stated,
            "compiler": results[0]["compiler"],
            "repetitions": [r["repetitions"] for r in results],
            "invocations": len(results),
            "runs_per_invocation": len(results[0]["runs_us"]),
            "invocation_medians_us": medians,
            "median_us": median(medians),
            "min_us": min(runs),
            "max_us": max(runs),
        })
    return {
        "measurement": "each family's fixed operation, and its further sized operations, per "
                       "backend and target, bench/operations.hpp",
        "date": utc_today(),
        "machine": machine(),
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "build": BUILD,
        "cases": out,
        "amd64_asm": AMD64_ASM,
    }


def measure_timing(exe):
    """The guard's cost, timing --measure's line, natively, with when, where and under what load
    it was measured."""
    loads = [os.getloadavg()]
    output = run("native", [exe, "--measure"])
    loads.append(os.getloadavg())
    result = program_line("native", [exe, "--measure"], output, TIMING_LINE_SHAPE)
    return {
        "measurement": "the nanoseconds detail::timing_guard adds to a call, bench/timing.cpp",
        "date": utc_today(),
        "machine": machine(),
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "build": BUILD,
        "target": result["target"],
        "compiler": result["compiler"],
        "iterations": result["iterations"],
        "runs": result["runs"],
        "dit": result["dit"],
        "clear_ns": result["clear"],
        "clear_fastest_ns": result["clear_fastest"],
        "clear_slowest_ns": result["clear_slowest"],
        "set_ns": result["set"],
        "set_fastest_ns": result["set_fastest"],
        "set_slowest_ns": result["set_slowest"],
    }


# What the page says above a table whose figures are provisional (--provisional).
PROVISIONAL = (
    "NOTE: these figures are provisional. They were measured on a shared machine under load "
    "(the load averages above), and are measured again in a final measurement pass on a quiet "
    "machine, once the work in progress has merged; read them as an upper bound."
)


# When the page warns that the machine was loaded: a shared machine shows in the spread before a
# single core is short, so the threshold is half the cores.
LOADED_RULE = "the larger of the two 1-minute load averages exceeds half the core count"


def loaded(data):
    """Whether the measurement ran on a loaded machine, by LOADED_RULE."""
    load = data["load_average_before_after"]
    return max(load[0][0], load[1][0]) > (data["machine"]["cores"] or 1) / 2


def fmt_load(load):
    return "/".join(f"{x:.0f}" for x in load)


def fmt_ns(value):
    """Nanoseconds as the page shows them: one decimal; "not recorded" for a figure the data,
    measured before it was recorded, does not hold."""
    return "not recorded" if value is None else f"{value:.1f}"


def fmt_us(value):
    """Microseconds as the page shows them: two decimals, or three significant digits below 1."""
    return f"{value:,.2f}" if value >= 1 else f"{value:.3g}"


def per_second(case):
    """What a cell does in a second: MiB for a seal, operations for the rest."""
    if case["operation"].startswith("seal of 16 KiB"):
        return f"{16 / 1024 / (case['median_us'] / 1e6):,.0f} MiB/s"
    return f"{1e6 / case['median_us']:,.0f} operations/s"


def render_timing(data, timing, titles, backends):
    """The guard's paragraph and table, from the data's "timing_guard", or the line saying it is
    not measured yet."""
    lines = [
        "[#crypto-performance-timing]",
        "==== The timing guard's cost",
        "",
        "Every public operation runs inside `detail::timing_guard`, which on 64-bit ARM under",
        "macOS, iOS, Linux and Android, where the CPU has FEAT_DIT, sets DIT (data-independent",
        "timing) for the call and restores the thread's state after it",
        "(<<crypto-backends-dit>>): one `mrs`, and where DIT was clear, two `msr`",
        "each followed by an `isb`. Elsewhere (x86, WebAssembly, Windows on ARM64) it executes",
        "no instruction.",
        "",
    ]
    if timing is None:
        return lines + ["Not measured yet.", ""]
    machine_info = timing["machine"]
    sets = ("The guard sets DIT on this machine." if timing["dit"] else
            "The guard does not set DIT on this machine (no FEAT_DIT, or a target it does not "
            "cover): both rows are the loop's noise.")
    load = timing["load_average_before_after"]
    lines += [
        f"Measured natively on {timing['date']} on {machine_info['cpu']}",
        f"({machine_info['architecture']}), {machine_info['os']}, built with {timing['build']}",
        f"by {timing['compiler']} (bench/timing.cpp): each row is the median of",
        f"{timing['runs']} runs of {timing['iterations']:,} guards around a store, with the",
        "fastest and slowest run beside it, each minus the median of the same loop without the",
        f"guard, in nanoseconds per call. {sets}",
        f"The machine's 1, 5 and 15 minute load averages were {fmt_load(load[0])} before and",
        f"{fmt_load(load[1])} after, on {machine_info['cores']} cores.",
        "",
    ]
    if timing.get("provisional"):
        lines += [PROVISIONAL, ""]
    if loaded(timing):
        lines += [
            "WARNING: the machine was shared and loaded while this was measured (rule: "
            + LOADED_RULE + ").",
            "",
        ]
    lines += [
        '[cols="2,4,1,1,1",options="header"]',
        "|===",
        "| The thread's DIT on entry | What the guard does | Median (ns) | Fastest (ns) "
        "| Slowest (ns)",
        "",
        "| clear, as a program that sets nothing has it",
        "| reads DIT, sets it, and clears it on the way out",
        f"| {fmt_ns(timing['clear_ns'])}",
        f"| {fmt_ns(timing.get('clear_fastest_ns'))}",
        f"| {fmt_ns(timing.get('clear_slowest_ns'))}",
        "",
        "| already set, by the program or by an outer guard",
        "| reads DIT and leaves it set",
        f"| {fmt_ns(timing['set_ns'])}",
        f"| {fmt_ns(timing.get('set_fastest_ns'))}",
        f"| {fmt_ns(timing.get('set_slowest_ns'))}",
        "|===",
        "",
    ]
    native = [c for c in data["cases"] if c["target"] == "native"]
    if native:
        shortest = min(native, key=lambda c: c["median_us"])
        lines += [
            "For scale, the shortest operation of the table above natively,",
            f"{titles[shortest['family']]} ({shortest['operation']}) on",
            f"{backends[shortest['backend']]}, takes {fmt_ns(shortest['median_us'] * 1000)} ns,",
            "its guard included.",
            "",
        ]
    return lines


def render(data, page):
    table = crypto_json()
    titles = {family["name"]: family["title"] for family in table["families"]}
    order = [family["name"] for family in table["families"]]
    backends = {name: facts["title"] for name, facts in table["backends"].items()}
    machine_info = data["machine"]
    lines = [
        "// Copyright (c) 2026 WebCpp.org",
        "//",
        "// Distributed under the Boost Software License, Version 1.0. (See",
        "// accompanying file LICENSE_1_0.txt or copy at",
        "// https://www.boost.org/LICENSE_1_0.txt)",
        "",
        "// Generated by bench/collect.py from doc/performance.json: do not edit.",
        "",
        "[#crypto-performance]",
        "=== Throughput",
        "",
        "How long each family's fixed operation, and each further operation the size matrix",
        "measures, takes on each backend and target, the operations the size matrix's programs",
        "call (bench/operations.hpp). A dated reference, measured by",
        "hand, that decides nothing: every default is chosen by the reason",
        "<<crypto-backends-defaults>> states, whatever these figures say.",
        "",
        f"Measured on {data['date']} on {machine_info['cpu']} ({machine_info['architecture']}),",
        f"{machine_info['cores']} cores, {machine_info['memory_gib']} GiB, {machine_info['os']};",
        f"WebAssembly under {machine_info['wasmtime']} (wasip2, wasip3) and node",
        f"{machine_info['node']} (Emscripten); built with {data['build']}. The CI's runners",
        "are measured when the owner runs this by hand on them.",
        "",
        "Each cell is the median of its invocations' medians, each of five timed runs, in",
        "microseconds per operation, with the fastest and slowest single run beside it: the",
        "spread is part of the result.",
        "",
    ]
    load = data["load_average_before_after"]
    lines += [
        f"The machine's 1, 5 and 15 minute load averages were {fmt_load(load[0])} before and",
        f"{fmt_load(load[1])} after, on {machine_info['cores']} cores.",
        "",
    ]
    if data.get("provisional"):
        lines += [PROVISIONAL, ""]
    if loaded(data):
        lines += [
            "WARNING: the machine was shared and loaded while this was measured (rule: "
            + LOADED_RULE + "). Read the spread, not a single figure.",
            "",
        ]
    lines += [
        '[cols="3,2,1,1,1,1,2",options="header"]',
        "|===",
        "| Operation | Backend | Target | Median (µs) | Fastest (µs) | Slowest (µs) "
        "| Per second",
    ]
    operations = {family["name"]: [family["measured"]] +
                  list(family.get("sized_operations", {}).values())
                  for family in table["families"]}

    def operation_rank(case):
        # A further operation crypto.json no longer states sorts after the stated ones.
        stated = operations[case["family"]]
        return stated.index(case["operation"]) if case["operation"] in stated else len(stated)

    cases = sorted(data["cases"], key=lambda c: (order.index(c["family"]), c["backend"],
                                                 operation_rank(c), TARGETS.index(c["target"])))
    for c in cases:
        lines += [
            "",
            f"| {titles[c['family']]}: {c['operation']}",
            f"| {backends[c['backend']]}",
            f"| {c['target']}",
            f"| {fmt_us(c['median_us'])}",
            f"| {fmt_us(c['min_us'])}",
            f"| {fmt_us(c['max_us'])}",
            f"| {per_second(c)}",
        ]
    lines += [
        "|===",
        "",
        "Compilers: " + "; ".join(
            f"{target}: {c['compiler']}" for target in TARGETS
            for c in [next((c for c in cases if c["target"] == target), None)] if c) + ".",
        "",
        "OpenSSL is not built for Emscripten, so its rows are native and WASI only; on WASI it",
        "is built `no-asm`, natively with its assembly.",
        "",
        "libsodium's x86-64 assembly (design D7): "
        + "; ".join(data["amd64_asm"]["rows"]) + f": {data['amd64_asm']['status']}. "
        + data["amd64_asm"]["reason"],
        "",
    ]
    lines += render_timing(data, data.get("timing_guard"), titles, backends)
    with open(page, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def check_shape(path, data):
    """Exits naming the first thing in data that is not what this script writes: a key missing or
    of another type, or a family, backend or target the page does not know."""
    found = wrong(data, DATA_SHAPE, "data")
    if found is None and data.get("timing_guard") is not None:
        found = wrong(data["timing_guard"], TIMING_SHAPE, "data.timing_guard", TIMING_OPTIONAL)
    if found is None and not isinstance(data.get("provisional", False), bool):
        found = "data.provisional"
    if found is None:
        table = crypto_json()
        known = {"family": {family["name"] for family in table["families"]},
                 "backend": set(table["backends"]), "target": set(TARGETS)}
        found = next((f"data.cases[{index}].{key} ({case[key]!r} is not one of crypto.json's)"
                      for index, case in enumerate(data["cases"])
                      for key, names in known.items() if case[key] not in names), None)
    if found is not None:
        sys.exit(f"collect.py: {path} is not the data collect.py writes: {found} is wrong; "
                 "measure it again with --exe")


def read_release_data(path):
    """The data at path; exits when it cannot be read, is not the data this script writes, or
    when it, or its guard's measurement, was not built at BUILD."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as error:
        sys.exit(f"collect.py: {path} cannot be read ({error}); --timing alone and --render-only "
                 "read the data that --exe wrote")
    if not isinstance(data, dict):
        sys.exit(f"collect.py: {path} is not the data collect.py writes: not a JSON object; "
                 "measure it again with --exe")
    if data.get("build") != BUILD:
        sys.exit(f"collect.py: {path} was measured with build {data.get('build')}, not "
                 f"{BUILD}: {RELEASE_ONLY}")
    timing = data.get("timing_guard")
    if isinstance(timing, dict) and timing.get("build") != BUILD:
        sys.exit(f"collect.py: {path}'s timing guard was measured with build "
                 f"{timing.get('build')}, not {BUILD}: {RELEASE_ONLY}")
    check_shape(path, data)
    return data


def write_data(path, data):
    """Writes data to path as the committed file has it."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Measures bench/throughput.cpp on each target.")
    parser.add_argument("--exe", action="append", default=[], metavar="TARGET=PATH")
    parser.add_argument("--invocations", type=int, default=5)
    parser.add_argument("--data", required=True)
    parser.add_argument("--page", required=True)
    parser.add_argument("--timing", metavar="PATH",
                        help="bench/Jamfile's timing at variant=release, run natively")
    parser.add_argument("--render-only", action="store_true")
    parser.add_argument("--provisional", action="store_true",
                        help="mark the figures of the part measured (--exe: the throughput, "
                             "--timing: the guard) as measured under load, to be measured again; "
                             "without it, a measurement clears its part's mark and keeps the "
                             "other's; with --render-only, mark both parts the data holds, "
                             "numbers unchanged")
    args = parser.parse_args()
    if args.render_only:
        data = read_release_data(args.data)
        if args.provisional:
            parts = [data] + ([data["timing_guard"]] if data.get("timing_guard") else [])
            unmarked = [part for part in parts if not part.get("provisional")]
            for part in unmarked:
                part["provisional"] = True
            if unmarked:
                write_data(args.data, data)
    else:
        exes = dict(item.split("=", 1) for item in args.exe)
        unknown = sorted(set(exes) - set(TARGETS))
        if unknown:
            sys.exit(f"collect.py: no target {', '.join(unknown)}; the targets are "
                     f"{', '.join(TARGETS)}")
        if not exes and args.timing is None:
            sys.exit("collect.py: nothing to measure: give --exe, --timing or --render-only")
        check_release({**exes, **({"timing": args.timing} if args.timing else {})})
        if exes:
            data = measure(exes, args.invocations)
            if args.timing is None and Path(args.data).exists():
                # The guard's cost is kept until it is measured again, with its own mark.
                kept = read_release_data(args.data).get("timing_guard")
                if kept is not None:
                    data["timing_guard"] = kept
            if args.provisional:
                data["provisional"] = True
        else:
            data = read_release_data(args.data)
        if args.timing is not None:
            data["timing_guard"] = measure_timing(args.timing)
            if args.provisional:
                data["timing_guard"]["provisional"] = True
        write_data(args.data, data)
    render(data, args.page)


if __name__ == "__main__":
    main()
