# GeekByte Lab

The test framework behind [GeekByte](https://geekbyte.com) Lab reports. It runs a frozen test plan's measurements on a Mac, records every attempt in a hash-chained ledger, and recomputes every published figure from that record.

Lab reports answer one question each by measurement on our own hardware, such as whether flash attention speeds up llama.cpp on an M5 Max. How we decide what to test and what we promise about the numbers is on our [standards page](https://geekbyte.com/standards/#lab).

## What is here

| File | What it does |
| --- | --- |
| `labrun.py` | The lab runner. It writes the plan's measurement scripts on the Mac, checks the installed engine builds and model files against the hashes the plan pre-registered, runs smoke runs, warm-ups and measured runs in seeded shuffled rounds, waits for a quiet machine before every run, and records each attempt with the log it captured. |
| `labverify.py` | The plan schema and the verifier. It checks the ledger's hash chain against the logs, recomputes every value and statistic, applies the plan's pre-registered comparisons, and writes the results block and the verdict. The plan format is documented at the top of this file. |
| `labstats.py` | The statistics: a confidence interval for the ratio of two means (Fieller's method, as Kalibera and Jones recommend for "A is x% faster" claims). |
| `gbmac` | The SSH helper the runner uses to reach the Mac as a Standard (non-admin) test account. |
| `check-report.py` | Re-checks a published report from its public files. |

Everything is Python 3 standard library and bash. There is no AI anywhere in this code. An AI agent designs the test, sets the Mac up by running the report's setup steps, and writes the text around the numbers. The runner then measures, and the verifier computes every figure.

## Re-check a published report

Every report publishes its plan, ledgers, runner logs, statistics and verdict under `https://geekbyte.com/lab/<slug>/`. To check that the numbers follow from the records:

```bash
git clone https://github.com/HollandDrive/GeekByte-Lab.git
cd GeekByte-Lab
python3 check-report.py llama-cpp-flash-attention-gemma-4-e4b-m5-max
```

It downloads the folder, checks every file against `SHA256SUMS`, checks the ledgers' hash chains and the runner code against the hashes the ledgers recorded, re-runs the verifier on the ledgers and logs, and compares the data, statistics and verdict it gets with the published ones. It prints `ok` when they match. It needs Python 3.10 or later and no Mac.

## Which version ran

This repository holds the current version. Each report's folder also has the exact code that produced it:

- `code/session1/` and `code/session2/`: the runner as each measuring session ran it. The ledger's session record holds the SHA-256 of every one of these files, and `check-report.py` compares them. A session interrupted and resumed on a later night resumes with the code it started with, and each resume record carries the same hashes. Sessions started before we published this code recorded the hash of `labrun.py` only (their ledgers have no `runner_files`), so for those the other files are the copy we kept with that `labrun.py`, not something the ledger proves. `check-report.py` says which kind each session is.
- `code/verify/`: the verifier that computed the report's statistics.

The current verifier can word a report's results differently from an older one. To reproduce a report's statistics exactly, use its `code/verify/` version.

## Run it yourself

You need a Mac with Apple silicon, reachable over SSH with key authentication, with a Standard user for the tests, and a Linux machine to drive it (on macOS, install GNU coreutils for `timeout`). Then:

```bash
export MAC_TEST_HOST=<your Mac's address> MAC_TEST_USER=<the test account>
d=$(./gbmac new)                     # a fresh folder in the test account's home
# set the Mac up with the report's setup steps (its "Reproduce it" section), then:
python3 labrun.py smoke plan.json ./run ./evidence "$d"      # checks and smoke runs only
python3 labrun.py run plan.json 1 ./run ./evidence "$d"      # session 1
python3 labverify.py verify plan.json ./run derived.md verdict.json ./evidence --slug=<slug>
```

`LABRUN_EXEC=local:<folder>` runs everything on the local machine instead of the Mac (we use it for tests). A published report's `plan.json` is a working example of a plan.

`gbmac` has more commands than the runner uses. The runner needs `run`, `info`, `labenv` and `new`. The `blocks` and `block` commands run a guide's code blocks and depend on our publishing pipeline, which is not in this repository.

## What it does not promise

- **The ledger shows edits, not authorship.** Each record carries the hash of the one before it, so an edit breaks the chain. Someone who can rewrite the whole ledger and its logs can also recompute the chain. The defence is that we publish the ledger with the report and do not change reports after publication. The one exception so far: on 16 November 2026 we added the `code/` folder to our first report's files, with new lines in its `SHA256SUMS`; no existing file or line changed.
- **A plan is code.** Its measurement scripts and command run on the Mac as the test account. Run only plans you have read.
- **`gbmac` is not a sandbox.** It points `HOME` at a temporary folder so installers stay inside it, refuses `sudo` and system-level commands, and refuses a command that contains the value of a local environment variable named like a key, token, secret or password. These are guard rails, not isolation. The real boundary is the Standard test account without admin rights. Use a dedicated account with nothing private in it.
- **The scrubber is narrow.** Before anything is published, logs and ledgers are scrubbed of IP addresses, user folders, email addresses and a local list of private words (`LAB_SCRUB_WORDS`, one word per line, never published). It does not detect every secret, so keep secrets out of the test account.
- **One machine.** Results come from our hardware and software builds. Our reports say which findings are properties of the software and which are true of our machine.
- **The gap between sessions.** A plan asks for its second session at least 12 hours after the first. Setting `LAB_SAME_DAY_OK=1` lets the verifier accept a shorter gap, and a report that relies on it must say so. `check-report.py` tells you when a report needed it.

## Found a problem?

Email editor@geekbyte.com with the report link. Corrections are noted at the top of the report.

## Licence

MIT. See [LICENSE](LICENSE).
