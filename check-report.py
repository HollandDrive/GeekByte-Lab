#!/usr/bin/env python3
"""Re-check a published GeekByte Lab report from its public files.

Downloads the report's folder from geekbyte.com (or reads a local copy), checks every file against its SHA256SUMS,
re-runs the verifier on the lab runner's ledgers and logs, and compares the data, statistics and verdict it computes
with the published ones. Where the report publishes the runner code each session ran (code/session<n>/), it also
checks that code against the hashes the session's ledger recorded.

Usage:
  python3 check-report.py <slug or folder>
  python3 check-report.py llama-cpp-flash-attention-gemma-4-e4b-m5-max
  python3 check-report.py ./my-copy-of-the-folder

Exit: 0 everything matches, 1 something does not, 2 usage or download error.
Standard library only (Python 3.10 or later). The verifier is labverify.py from this folder, so a report published
with an older verifier can differ in wording; the report's own verifier is in its code/verify/ folder.
"""
import gzip
import http.client
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]   # beside it in GeekByte-Lab; one folder up in the pipeline's copy
import labverify  # noqa: E402

BASE = 'https://geekbyte.com/lab/'
SAFE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$')   # relative, no '..', no '//'
SLUG = re.compile(r'^[a-z0-9][a-z0-9-]{0,120}$')
LOG = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,250}$')
CODE = {'labrun.py', 'labverify.py', 'labstats.py', 'gbmac'}
MAX_FILE = 64 << 20        # one published file (the publishing limit for the raw logs is 20 MB)
MAX_TOTAL = 256 << 20      # everything downloaded
MAX_FILES = 500            # entries in SHA256SUMS
MAX_MEMBERS = 50000        # files in raw-logs.tar.gz
MAX_EXPANDED = 512 << 20   # raw-logs.tar.gz unpacked


class Stop(Exception):
    pass


def safe(rel):
    return bool(SAFE.match(rel)) and '..' not in rel.split('/')


def copy_limited(f, out, limit):
    n = 0
    with open(out, 'wb') as o:
        while True:
            b = f.read(1 << 20)
            if not b:
                return n
            n += len(b)
            if n > limit:
                raise Stop(f'{os.path.basename(out)} is larger than {limit >> 20} MB')
            o.write(b)


def fetch(src, rel, dst, budget):
    """Copy one published file into dst (from the site or a local folder). False when it is not there."""
    out = os.path.join(dst, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.isdir(src):
        p = os.path.join(src, rel)
        real = os.path.realpath(p)
        if os.path.islink(p) or not real.startswith(os.path.realpath(src) + os.sep) or not os.path.isfile(real):
            return False
        with open(real, 'rb') as f:
            n = copy_limited(f, out, min(MAX_FILE, budget[0]))
    else:
        req = urllib.request.Request(BASE + src + '/' + rel, headers={'User-Agent': 'geekbyte-lab-check/1'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                n = copy_limited(r, out, min(MAX_FILE, budget[0]))
        except (OSError, http.client.HTTPException):
            return False
    budget[0] -= n
    return True


def unpack(tgz, run):
    """The runner's logs from raw-logs.tar.gz into run/raw/, regular files only, within the limits. The archive is
    decompressed to a size-capped file first, so no header or entry is read beyond the limit."""
    total = members = 0
    tar_path = tgz[:-3]
    with gzip.open(tgz, 'rb') as f:
        copy_limited(f, tar_path, MAX_EXPANDED)
    with tarfile.open(tar_path, 'r:') as tar:
        for m in tar:
            members += 1
            if members > MAX_MEMBERS:
                raise Stop(f'raw-logs.tar.gz has more than {MAX_MEMBERS} entries')
            if not m.isfile():
                continue
            if not safe(m.name) or not m.name.startswith('raw/'):
                raise Stop(f'raw-logs.tar.gz has an unexpected entry {m.name!r}')
            total += m.size
            if total > MAX_EXPANDED:
                raise Stop(f'raw-logs.tar.gz unpacks to more than {MAX_EXPANDED >> 20} MB')
            out = os.path.join(run, m.name)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with tar.extractfile(m) as f:
                copy_limited(f, out, m.size)


def check(src, work):
    pub = os.path.join(work, 'published')
    bad = []
    budget = [MAX_TOTAL]
    if not fetch(src, 'SHA256SUMS', pub, budget):
        raise Stop(f'could not get SHA256SUMS for {src}')
    sums = {}
    for n, line in enumerate(open(os.path.join(pub, 'SHA256SUMS'), encoding='utf-8', errors='replace'), 1):
        m = re.match(r'^([0-9a-f]{64})  (.+)$', line.rstrip('\n'))
        if not m or not safe(m.group(2)) or m.group(2) == 'SHA256SUMS':
            bad.append(f'SHA256SUMS line {n}: not a "<sha256>  <relative path>" line')
        elif m.group(2) in sums:
            bad.append(f'SHA256SUMS line {n}: {m.group(2)} is listed twice')
        else:
            sums[m.group(2)] = m.group(1)
    if len(sums) > MAX_FILES:
        raise Stop(f'SHA256SUMS lists more than {MAX_FILES} files')
    for rel, want in sorted(sums.items()):
        if not fetch(src, rel, pub, budget):
            bad.append(f'{rel}: listed in SHA256SUMS but not published')
        elif labverify.sha256_file(os.path.join(pub, rel)) != want:
            bad.append(f'{rel}: does not match its SHA-256 sum')
    print(f'checked {len(sums)} files against SHA256SUMS: {"ok" if not bad else "problems"}')
    for need in ('plan.json', 'ledger-session1.jsonl', 'derived.txt', 'verdict.json', 'data.csv'):
        if need not in sums:
            raise Stop(f'{need} is not in the report folder; nothing to re-check')

    # Lay the published files out as the verifier reads them: the runner's logs under raw/, the ledgers by session.
    run, evid = os.path.join(work, 'run'), os.path.join(work, 'evidence')
    os.makedirs(run)
    os.makedirs(evid)
    if 'raw-logs.tar.gz' in sums:
        unpack(os.path.join(pub, 'raw-logs.tar.gz'), run)
    sessions = '2' if 'ledger-session2.jsonl' in sums else '1'
    for k in ('1', '2')[:int(sessions)]:
        shutil.copyfile(os.path.join(pub, f'ledger-session{k}.jsonl'), os.path.join(evid, f'lab-ledger-s{k}.jsonl'))
        recs, err = labverify.read_ledger(os.path.join(evid, f'lab-ledger-s{k}.jsonl'))
        if err:
            bad.append(f'session {k} ledger: {err}')
        logs = [r.get('log') for r in recs if r.get('log') is not None]
        if any(not isinstance(x, str) or not LOG.match(x) for x in logs):
            raise Stop(f'session {k} ledger names a log outside the runner\'s log folder')
        # The runner code each session ran, against the hashes its ledger recorded.
        found = len(bad)
        hi = [i for i, r in enumerate(recs) if r.get('type') == 'session']
        head = recs[hi[-1]] if hi else {}
        full = bool(head.get('runner_files'))
        want = head.get('runner_files') or {'labrun.py': head.get('runner_sha256', '')}
        if not isinstance(want, dict) or set(want) - CODE:
            bad.append(f'session {k} ledger: unexpected runner_files')
            continue
        # Resumed with the code it started with: every resume record's hashes are the header's (an older header
        # recorded labrun.py only, so that one is compared).
        for r in recs[hi[-1] if hi else 0:]:
            f = r.get('runner_files') if r.get('type') == 'resume' else None
            if f is not None and (f != want if full else f.get('labrun.py') != want.get('labrun.py')):
                bad.append(f'session {k} was resumed with different runner code than it started with')
                break
        if not any(rel.startswith(f'code/session{k}/') for rel in sums):
            if full:
                bad.append(f'session {k}: its ledger names the runner code but code/session{k}/ is not published')
            else:
                print(f'session {k}: runner {str(want.get("labrun.py", "?"))[:12]} (its code is not in this report folder)')
            continue
        for n, h in sorted(want.items()):
            p = os.path.join(pub, 'code', f'session{k}', n)
            if f'code/session{k}/{n}' not in sums or labverify.sha256_file(p) != h:
                bad.append(f'code/session{k}/{n}: not the code the session ledger recorded')
        if len(bad) == found:
            print(f'session {k}: runner code matches the ledger ({len(want)} file(s)'
                  f'{"" if full else "; this ledger recorded labrun.py only, the other files are not proven by it"})')

    plan = json.load(open(os.path.join(pub, 'plan.json')))
    slug = plan.get('slug') if isinstance(plan, dict) else None
    if not isinstance(slug, str) or not SLUG.match(slug):
        raise Stop('plan.json has no usable slug')
    # The measurement scripts published in scripts/ are the ones frozen in the plan.
    files = ((plan.get('lab') or {}).get('files') or {}) if isinstance(plan.get('lab'), dict) else {}
    for rel in sorted(r for r in sums if r.startswith('scripts/')):
        want_text = files.get(rel[len('scripts/'):]) if isinstance(files, dict) else None
        if want_text is None or open(os.path.join(pub, rel), 'rb').read() != str(want_text).encode('utf-8'):
            bad.append(f'{rel}: not the measurement script frozen in plan.json')
    if 'code/verify/labverify.py' in sums:
        print('code/verify/ holds the verifier this report was published with (its hashes are in SHA256SUMS)')
    args = (os.path.join(pub, 'plan.json'), run, os.path.join(work, 'derived.md'), os.path.join(work, 'verdict.json'), evid)
    rc = labverify.lab_verify(*args, slug=slug, sessions=sessions)
    mine = json.load(open(os.path.join(work, 'verdict.json')))
    gap = [p for p in mine.get('hold', []) if 'session 2 started' in p and 'the plan needs at least' in p]
    if rc and gap and len(gap) == len(mine.get('hold', [])):
        print(f'note: {gap[0].replace("verification: ", "")}. Re-checking with that allowed; the report must say so.')
        os.environ['LAB_SAME_DAY_OK'] = '1'
        rc = labverify.lab_verify(*args, slug=slug, sessions=sessions)
        mine = json.load(open(os.path.join(work, 'verdict.json')))
    if json.dumps(mine, sort_keys=True) != json.dumps(json.load(open(os.path.join(pub, 'verdict.json'))), sort_keys=True):
        bad.append('verdict.json: the verdict computed here differs from the published one')
    pairs = [('derived.md', 'derived.txt'), (f'run/{slug}-data.csv', 'data.csv')]
    if sessions == '2':
        pairs.append((f'run/{slug}-data-s2.csv', 'data-session2.csv'))
    for mine_f, theirs in pairs:
        p = os.path.join(work, mine_f)
        got = labverify.scrub(open(p, encoding='utf-8').read()) if os.path.exists(p) else None
        if theirs not in sums or got != open(os.path.join(pub, theirs), encoding='utf-8').read():
            bad.append(f'{theirs}: differs from what the verifier computes from the ledgers and logs')
    if rc:
        bad.append(f'the verifier found problems: {"; ".join(mine.get("hold", []))}')
    return bad


def main(argv):
    if len(argv) != 1:
        print(__doc__)
        return 2
    src = argv[0].rstrip('/')
    if not os.path.isdir(src) and not SLUG.match(src):
        print('give a report slug (the part after /lab/ in its URL) or a local folder')
        return 2
    work = tempfile.mkdtemp(prefix='gb-lab-check-')
    try:
        bad = check(src, work)
    except Stop as e:
        print(f'stopped: {e}')
        return 2
    except (ValueError, KeyError, TypeError, AttributeError, OSError, EOFError, tarfile.TarError, zlib.error,
            http.client.HTTPException) as e:
        print(f'stopped: a published file could not be read as expected ({e.__class__.__name__}: {e})')
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if bad:
        print('\n'.join(['PROBLEMS:'] + [f'- {b}' for b in bad]))
        return 1
    print('ok: the published data, statistics and verdict match what the verifier computes from the ledgers and logs')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
