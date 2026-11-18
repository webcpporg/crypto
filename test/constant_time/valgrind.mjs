// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Runs the program under Valgrind's memcheck and passes with its exit status: 99 when
// memcheck found a use of an undefined value, which a branch on a secret is.
// With --expect-leak, it passes only when memcheck found one: the planted leak's build.
import {spawnSync} from 'node:child_process'
import {dirname, join} from 'node:path'
import {fileURLToPath} from 'node:url'

const program = process.argv[process.argv.length - 1]
const expectLeak = process.argv.includes('--expect-leak')
const suppressions = join(dirname(fileURLToPath(import.meta.url)), 'openssl.supp')
const run = spawnSync('valgrind', ['--error-exitcode=99', '--track-origins=yes', '--quiet',
    `--suppressions=${suppressions}`, program], {stdio: 'inherit'})
if (run.error) {
    console.error(`valgrind could not run: ${run.error.message}; install valgrind (Linux)`)
    process.exit(1)
}
if (expectLeak) {
    process.exit(run.status === 99 ? 0 : 1)
}
process.exit(run.status ?? 1)
