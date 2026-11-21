// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Runs the program under Valgrind's memcheck and passes with its exit status: 99 when
// memcheck found a use of an undefined value, which a branch on a secret is.
// With --expect-leak, it passes only when memcheck found one: the planted leak's build; with
// --in <function> besides, only when a report's first frame is in that function: the planted
// copy of P-256's scalar check.
// Suppressed: libsodium's and BearSSL's own branches on a verdict (sodium_verdicts.supp,
// bearssl_verdicts.supp), and OpenSSL's start-up frames (openssl.supp).
import {spawnSync} from 'node:child_process'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'

const program = process.argv[process.argv.length - 1]
const expectLeak = process.argv.includes('--expect-leak')
const inAt = process.argv.indexOf('--in')
const plantedIn = inAt === -1 ? undefined : process.argv[inAt + 1]
const here = dirname(fileURLToPath(import.meta.url))
const run = spawnSync('valgrind', ['--error-exitcode=99', '--track-origins=yes', '--quiet',
    `--suppressions=${join(here, 'openssl.supp')}`,
    `--suppressions=${join(here, 'sodium_verdicts.supp')}`,
    `--suppressions=${join(here, 'bearssl_verdicts.supp')}`, program],
    {stdio: ['inherit', 'inherit', plantedIn === undefined ? 'inherit' : 'pipe'], encoding: 'utf8'})
if (run.error) {
    console.error(`valgrind could not run: ${run.error.message}; install valgrind (Linux)`)
    process.exit(1)
}
if (plantedIn !== undefined) {
    process.stderr.write(run.stderr ?? '')
}
if (expectLeak) {
    // memcheck's report: the error's line, then its frames, the first "at", the next "by".
    const named = plantedIn === undefined ||
        new RegExp(`^==\\d+==\\s+at 0x[0-9A-F]+: .*\\b${plantedIn}\\b`, 'm').test(run.stderr ?? '')
    process.exit(run.status === 99 && named ? 0 : 1)
}
process.exit(run.status ?? 1)
