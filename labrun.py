#!/usr/bin/env python3
"""GeekByte Lab runner: runs a frozen lab plan's measurements on the Mac and records every attempt.

The tester sets the machine up (installs the pinned builds, downloads the models, builds the prompts) by running the
report's setup steps. It does not measure. This runner then, with no agent involved:
  1. checks it is connected as the test account, stops anything that account left running, writes the plan's
     measurement scripts (lab.files) itself and checks their SHA-256 on the Mac, checks the installed files against
     the official identities the plan pre-registered (lab.expect), and fingerprints lab.inputs with SHA-256;
  2. runs the smoke cells (a broken setup stops here, exit 3, before hours are spent);
  3. runs the warm-ups, then the measured runs in rounds, each round a seeded shuffle of the cells that still need runs;
     before every attempt it stops leftover processes and waits for the plan's conditions (load, CPU, other memory,
     thermal state) and a cool-down, so each run is a fresh process on a quiet machine;
  4. writes a start record before each attempt launches, then classifies the attempt from the log it captured itself
     (ok, invalid, failed, timeout; an attempt that never finished is invalid), retries invalid and failed ones up to
     lab.max_retries per cell, and records timeouts without retrying;
  5. at the end fingerprints the inputs and checks lab.expect again, so a file changed during the session shows.
Every record goes into a hash-chained ledger outside the run directory, scrubbed of private details as it is written.

Usage:
  labrun.py run <plan.json> <session 1|2> <rundir> <evidence dir> <mac dir>
  labrun.py smoke <plan.json> <rundir> <evidence dir> <mac dir>   checks and smoke runs only, in their own ledger
      (lab-ledger-smoke.jsonl) and logs (raw/runner-smoke): the design check before a plan is frozen
Exit: 0 done (end record written), 3 the setup is broken (smoke failed, inputs missing or not the files the plan names,
or for session 2 not the same files as session 1; fix the setup and run again), 4 stopped at the deadline (end record
written; unrun slots stay unrun), 5 the Mac or the session broke (resume by running again), 7 too early for session 2
(the plan's min_gap_hours), 2 usage or plan.
Resume: running the same session again continues from the ledger.

LABRUN_EXEC=local:<dir> runs everything locally in <dir> instead of on the Mac (tests only).
"""
import base64
import datetime as dt
import fcntl
import hashlib
import json
import os
import random
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import labverify as lv  # noqa: E402

MAX_LOG = 20 * 1024 * 1024
SYSTEM_PREFIXES = ('/usr/libexec/', '/usr/sbin/', '/System/', '/Library/Apple/', '/sbin/', '/usr/bin/ssh-agent',
                   '/Applications/', '/Library/Application Support/')


RUNNER_FILES = ('labrun.py', 'labverify.py', 'labstats.py', 'gbmac')


def runner_files():
    """SHA-256 of the code that measures (this runner, the module it imports and the Mac helper), for the ledger."""
    return {n: lv.sha256_file(os.path.join(HERE, n)) for n in RUNNER_FILES if os.path.exists(os.path.join(HERE, n))}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


# ---------------------------------------------------------------------------------------------------- executors

class RunnerError(Exception):
    """The Mac or the session is in a state the runner cannot trust (the session stops; it resumes later)."""


PROC_SCRIPT = r""": GBPROCLIST
echo "GBUSER $(id -un)"
anc=" $$ "; p=$$
while [ "${p:-1}" -gt 1 ]; do p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' '); anc="$anc$p "; done
ps -U "$(id -u)" -o pid=,rss=,pcpu=,command= | while read -r pid rss cpu cmd; do
  case "$anc" in *" $pid "*) continue ;; esac
  case "$cmd" in *GBPROCLIST*|sshd*|-bash|-zsh|-sh|"ps -U"*) continue ;; esac
  echo "GBPROC $pid $rss $cpu $cmd"
done
echo "GBPROCEND"
"""

COND_SCRIPT = r"""
echo "GBCOND load1=$(sysctl -n vm.loadavg | awk '{print $2}')"
echo "GBCOND therm=$(pmset -g therm 2>/dev/null | tr -s ' ' | tr '\n' ';')"
ps -Ao pcpu=,rss=,user=,comm= -r | awk 'NR<=6 {print "GBTOP " $0}'
ps -Ao rss=,pcpu=,user=,comm= -m | awk 'NR<=4 {print "GBMEM " $0}'
echo "GBCOND pressure=$(memory_pressure -Q 2>/dev/null | tail -1)"
"""

# Fingerprints that survive a fresh setup on another day: no byte-code caches, and the session's own HOME path (which
# differs per session directory, for example in a virtual environment's scripts) replaced by $HOME before hashing.
# Files over 50 MB (model weights) are hashed as they are.
HASH_SCRIPT = r"""cd "$HOME" || exit 2
for g in @GLOBS@; do
  if [ -d "$g" ]; then find -L "$g" -type f ! -path '*/__pycache__/*' ! -name '*.pyc'
  elif [ -e "$g" ]; then echo "$g"; else echo "GBMISSING $g"; fi
done | LC_ALL=C sort | while IFS= read -r f; do
  case "$f" in
    "GBMISSING "*) echo "$f" ;;
    *) sz=$(wc -c < "$f" | tr -d ' ')
       if [ "$sz" -lt 52428800 ]; then h=$(LC_ALL=C sed "s|$HOME|\$HOME|g" "$f" | (shasum -a 256 2>/dev/null || sha256sum) | cut -c1-64)
       else h=$( (shasum -a 256 "$f" 2>/dev/null || sha256sum "$f") | cut -c1-64); fi
       echo "$h  $f" ;;
  esac
done
echo GBHASHEND
"""

# Python packages named in lab.expect: installed version and every file against the package's own RECORD hashes.
EXPECT_PY = r"""
import base64, hashlib, importlib.metadata as md, json, sys
want = json.loads(sys.argv[1]); bad = []
for name, ver in want.items():
    try:
        d = md.distribution(name)
    except md.PackageNotFoundError:
        bad.append(f"{name}: not installed"); continue
    if d.version != ver:
        bad.append(f"{name}: version {d.version}, plan says {ver}")
    n = 0
    for f in d.files or []:
        if not f.hash or "__pycache__" in str(f):
            continue
        try:
            got = base64.urlsafe_b64encode(hashlib.new(f.hash.mode, open(f.locate(), "rb").read()).digest()).rstrip(b"=").decode()
        except OSError:
            bad.append(f"{name}: {f} missing"); continue
        n += 1
        if got != f.hash.value:
            bad.append(f"{name}: {f} differs from the package's own RECORD")
    if not n:
        bad.append(f"{name}: no hashed files in RECORD")
print("GBEXPECT " + json.dumps(bad))
"""


class Mac:
    """Commands on the Mac through newsroom/gbmac (SSH as the Standard test user), in the session directory."""
    proc_script, cond_script = PROC_SCRIPT, COND_SCRIPT

    def __init__(self, macdir):
        self.dir = macdir
        self.user = os.environ.get('MAC_TEST_USER', '')
        if not self.user:
            raise SystemExit('labrun: MAC_TEST_USER (the Mac test account) is not set')
        self.env = {k: v for k, v in os.environ.items() if k not in ('GB_EVIDENCE', 'GB_RECORDING')}

    def sh(self, script, timeout):
        cmd = ['timeout', '--kill-after=30', str(int(timeout)), os.path.join(HERE, 'gbmac'), 'run', self.dir, script]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=self.env, timeout=timeout + 60)
            out, rc = p.stdout, p.returncode
        except subprocess.TimeoutExpired as e:
            out, rc = e.stdout or b'', 124
        return rc, out[:MAX_LOG].decode('utf-8', 'replace'), rc in (124, 137)

    def gbmac(self, *args, timeout=120):
        p = subprocess.run(['timeout', str(timeout), os.path.join(HERE, 'gbmac'), *args], capture_output=True, text=True, env=self.env)
        return p.returncode, p.stdout + p.stderr


class Local(Mac):
    """Tests: the same commands run locally with HOME inside <dir>. Only processes whose command line contains <dir>
    are listed or stopped, never anything else of this account."""
    proc_script = (r'[ -f "$LABRUN_DIR/break-procs" ] && exit 3; echo "GBUSER local"; ps -u "$(id -u)" -o pid=,rss=,pcpu=,command= | grep -F -- "$LABRUN_DIR" '
                   r'| grep -v -e "grep -F" -e "ps -u" | while read -r pid rss cpu cmd; do '
                   r'[ "$pid" = "$$" ] || echo "GBPROC $pid $rss $cpu $cmd"; done; echo GBPROCEND')
    cond_script = (r'if [ -f "$HOME/../cond.txt" ]; then cat "$HOME/../cond.txt"; else echo "GBCOND load1=0.10"; '
                   r'echo "GBCOND therm=Note: No thermal warning level has been recorded"; echo "GBTOP 0.1 100 sim idle"; fi')

    def __init__(self, d):
        self.dir = d
        self.user = 'local'
        os.makedirs(os.path.join(d, 'home'), exist_ok=True)
        self.env = {**{k: v for k, v in os.environ.items() if k not in ('GB_EVIDENCE', 'GB_RECORDING')},
                    'HOME': os.path.join(d, 'home'), 'LABRUN_DIR': d}

    def sh(self, script, timeout):
        try:
            p = subprocess.run(['bash', '-c', f'cd "$HOME" && {script}'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=self.env, timeout=timeout, start_new_session=True)
            return p.returncode, p.stdout[:MAX_LOG].decode('utf-8', 'replace'), False
        except subprocess.TimeoutExpired as e:
            return 124, (e.stdout or b'').decode('utf-8', 'replace'), True

    def gbmac(self, *args, timeout=120):
        return 0, ''


# ---------------------------------------------------------------------------------------------------- ledger

class Ledger:
    def __init__(self, path):
        self.path = path
        self.recs, err = lv.read_ledger(path) if os.path.exists(path) else ([], None)
        if err:
            raise SystemExit(f'labrun: {err}; refusing to append to a broken ledger')
        self.prev = self.recs[-1]['hash'] if self.recs else '0' * 64

    def add(self, rec):
        rec = json.loads(lv.scrub(json.dumps(rec, ensure_ascii=False)))  # nothing private enters the ledger
        rec['prev'] = self.prev
        rec['hash'] = lv.chain_hash(self.prev, rec)
        with open(self.path, 'a', encoding='utf-8') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + '\n')
            f.flush()
            os.fsync(f.fileno())
        self.prev = rec['hash']
        self.recs.append(rec)
        return rec


# ---------------------------------------------------------------------------------------------------- the runner

def parse_conditions(out, cond):
    """Parse the conditions probe. Anything the plan enforces that cannot be read counts as not met."""
    c = {}
    for line in out.splitlines():
        m = re.match(r'GBCOND (\w+)=(.*)$', line)
        if m:
            c[m.group(1)] = m.group(2).strip()
    try:
        c['load1'] = float(c.get('load1', 'nan'))
    except ValueError:
        c['load1'] = float('nan')
    therm = c.get('therm', '')
    limits = [int(x) for x in re.findall(r'Speed_Limit\s*=\s*(\d+)', therm)]
    c['thermal_warning'] = bool(re.search(r'warning level\s*=\s*[1-9]', therm, re.I)) or any(x < 100 for x in limits)
    tops = []
    for line in out.splitlines():
        if line.startswith('GBTOP '):
            parts = line.split(None, 4)
            if len(parts) >= 5:
                try:
                    tops.append((float(parts[1]), int(parts[2]), parts[3], parts[4]))
                except ValueError:
                    pass
    busy = [t for t in tops if not re.search(r'(^|/)(ps|awk|sysctl|pmset|memory_pressure|bash|sshd.*)$', t[3])]
    c['top_cpu'] = busy[0][0] if busy else 0.0
    c['top_cpu_proc'] = f'{busy[0][2]} {busy[0][3]}' if busy else ''
    mems = []
    for line in out.splitlines():
        if line.startswith('GBMEM '):
            parts = line.split(None, 4)
            if len(parts) >= 5:
                try:
                    mems.append((int(parts[1]) / 1048576, parts[3], parts[4]))
                except ValueError:
                    pass
    c['top_rss_gb'] = round(mems[0][0], 2) if mems else 0.0
    c['top_rss_proc'] = f'{mems[0][1]} {mems[0][2]}' if mems else ''
    bad = []
    if c['load1'] != c['load1']:
        bad.append('load average unreadable')
    elif not c['load1'] <= cond['max_load1']:
        bad.append(f'load {c["load1"]} > {cond["max_load1"]}')
    if not tops:
        bad.append('process list unreadable')
    elif c['top_cpu'] > cond['max_cpu_pct']:
        bad.append(f'{c["top_cpu_proc"]} at {c["top_cpu"]}% CPU')
    if c['top_rss_gb'] > cond['max_other_rss_gb']:
        bad.append(f'{c["top_rss_proc"]} holds {c["top_rss_gb"]} GB')
    if cond.get('no_thermal_warning'):
        if not therm.strip():
            bad.append('thermal state unreadable')
        elif c['thermal_warning']:
            bad.append('thermal warning: ' + therm[:120])
    return c, bad


class Runner:
    def __init__(self, plan_path, session, rundir, evid, macdir, smoke_only=False):
        self.plan_path = plan_path
        self.plan = json.load(open(plan_path))
        self.lab = lv.lab_conf(self.plan)
        self.session = session
        self.rundir = rundir
        # Smoke only (the design check before a plan is frozen): its own logs and ledger, never a session's.
        self.smoke_only = smoke_only
        name = 'smoke' if smoke_only else f's{session}'
        self.logdir = os.path.join(rundir, 'raw', f'runner-{name}')
        os.makedirs(self.logdir, exist_ok=True)
        os.makedirs(evid, exist_ok=True)
        self.ledger = Ledger(os.path.join(evid, f'lab-ledger-{name}.jsonl'))
        ex = os.environ.get('LABRUN_EXEC', '')
        self.x = Local(ex.split(':', 1)[1]) if ex.startswith('local:') else Mac(macdir)
        self.planned = lv.cells_of(self.lab, session)
        self.cells = {lv.cell_key(c): c for spec in self.lab['cells'] for c in lv.expand(spec)}
        self.deadline = None
        self.seq = max([r.get('seq', 0) for r in self.ledger.recs if r.get('type') in ('attempt', 'start')] + [0])
        self.sleep = time.sleep

    # -- helpers
    def say(self, msg):
        print(f'[{dt.datetime.now(dt.timezone.utc).strftime("%H:%M:%S")}] labrun: {msg}', flush=True)

    def wd(self):
        return '"$HOME"/' + shlex.quote(self.lab['workdir'])

    def procs(self):
        """The test account's own leftover processes. Raises if the list cannot be read or the session is not the test
        account (then nothing is stopped)."""
        rc, out, _ = self.x.sh(self.x.proc_script, 60)
        m = re.search(r'^GBUSER (\S+)$', out, re.M)
        if rc != 0 or 'GBPROCEND' not in out or not m:
            raise RunnerError(f'could not list the test account\'s processes (rc {rc})')
        if m.group(1) != self.x.user:
            raise RunnerError(f'connected as {m.group(1)}, not the test account {self.x.user}; nothing was stopped')
        rows = []
        for line in out.splitlines():
            if line.startswith('GBPROC '):
                parts = line.split(None, 4)
                if len(parts) == 5:
                    rows.append({'pid': parts[1], 'rss_kb': parts[2], 'cpu': parts[3], 'cmd': lv.scrub(parts[4][:200])})
        return [r for r in rows if not r['cmd'].startswith(SYSTEM_PREFIXES)]

    def reap(self):
        """Stop every process the test account left behind (servers, background batches) and check that they are
        gone. Returns (stopped, survivors)."""
        left = self.procs()
        if not left:
            return [], []
        pids = ' '.join(r['pid'] for r in left if r['pid'].isdigit())
        self.x.sh(f'kill -TERM {pids} 2>/dev/null; sleep 5; kill -KILL {pids} 2>/dev/null; sleep 1; true', 60)
        gone = {r['pid'] for r in left}
        survivors = [r for r in self.procs() if r['pid'] in gone]
        return left, survivors

    def conditions(self):
        rc, out, _ = self.x.sh(self.x.cond_script, 60)
        c, bad = parse_conditions(out, self.lab['conditions'])
        if rc != 0:
            bad.append(f'conditions probe failed (rc {rc})')
        return c, bad

    def write_files(self):
        parts = [f'mkdir -p {self.wd()}', f'cd {self.wd()}']
        for p, content in sorted((self.lab.get('files') or {}).items()):
            b = base64.b64encode(content.encode()).decode()
            mode = '755' if content.startswith('#!') or p.endswith('.sh') else '644'
            parts.append(f'mkdir -p "$(dirname {shlex.quote(p)})" && printf %s {b} | base64 --decode > {shlex.quote(p)} && chmod {mode} {shlex.quote(p)}')
        names = ' '.join(shlex.quote(p) for p in sorted(self.lab.get('files') or {}))
        if names:
            parts.append(f'(shasum -a 256 {names} 2>/dev/null || sha256sum {names})')
        rc, out, _ = self.x.sh(' && '.join(parts), 300)
        got = {}
        for line in out.splitlines():
            m = re.match(r'^([0-9a-f]{64})\s+\*?(.+)$', line.strip())
            if m:
                got[m.group(2)] = m.group(1)
        return rc, got, out

    def hash_inputs(self):
        globs = ' '.join(shlex.quote(g) if not re.search(r'[*?]', g) else g for g in self.lab['inputs'])
        rc, out, _ = self.x.sh(HASH_SCRIPT.replace('@GLOBS@', globs), 3600)
        h, missing = {}, []
        for line in out.splitlines():
            if line.startswith('GBMISSING '):
                missing.append(line[10:])
                continue
            m = re.match(r'^([0-9a-f]{64})\s+\*?(.+)$', line.strip())
            if m:
                h[m.group(2)] = m.group(1)
        if 'GBHASHEND' not in out:
            rc = rc or 1
        return rc, h, missing

    def _sha(self, rel, timeout=1800):
        q = shlex.quote(rel)
        rc, out, _ = self.x.sh(f'cd "$HOME" && (shasum -a 256 {q} 2>/dev/null || sha256sum {q})', timeout)
        return out.split()[0] if rc == 0 and out.split() else ''

    def check_expect(self):
        """The plan's official identities (lab.expect). Returns a list of problems (empty when all match)."""
        bad = []
        for e in self.lab.get('expect') or []:
            if 'path' in e:
                got = self._sha(e['path'])
                if got != e['sha256']:
                    bad.append(f'{e["path"]}: SHA-256 {got[:16] or "unreadable"}, plan says {e["sha256"][:16]}')
            elif 'archive' in e:
                got = self._sha(e['archive'])
                if got != e['sha256']:
                    bad.append(f'{e["archive"]}: SHA-256 {got[:16] or "unreadable"}, plan says {e["sha256"][:16]}')
                    continue
                a = shlex.quote(e['archive'])
                ext = 'unzip -p' if e['archive'].endswith('.zip') else 'tar -xOf'
                for inst, member in sorted((e.get('members') or {}).items()):
                    rc, out, _ = self.x.sh(f'cd "$HOME" && {ext} {a} {shlex.quote(member)} | cmp -s - {shlex.quote(inst)} && echo GBSAME', 600)
                    if 'GBSAME' not in out:
                        bad.append(f'{inst}: differs from {member} in the verified archive {e["archive"]}')
            elif 'python' in e:
                rc, out, _ = self.x.sh(f'cd "$HOME" && {shlex.quote(e["python"])} -I -c {shlex.quote(EXPECT_PY)} '
                                       f'{shlex.quote(json.dumps(e["packages"]))}', 600)
                m = re.search(r'^GBEXPECT (.*)$', out, re.M)
                if not m:
                    bad.append(f'{e["python"]}: could not check the packages (rc {rc})')
                else:
                    bad += json.loads(m.group(1))
        return bad

    def command(self, cell, kind, run_id):
        vals = {**cell, 'kind': kind, 'run_id': run_id, 'session': str(self.session)}
        cmd = self.lab['command'].format(**{k: shlex.quote(str(v)) for k, v in vals.items()})
        env = f'GB_KIND={kind} GB_RUN_ID={shlex.quote(run_id)} GB_SESSION={self.session}'
        return f'cd {self.wd()} && export {env} && {cmd}'

    # -- one attempt
    def attempt(self, cell, kind, rnd=None):
        self.seq += 1
        seq = self.seq
        k = lv.cell_key(cell)
        run_id = f's{self.session}-{seq:04d}'
        base = {'seq': seq, 'kind': kind, 'round': rnd, 'cell': dict(zip(lv.CELL_KEYS, k)), 'run_id': run_id}
        cond = self.lab['conditions']
        if seq > 1 and cond.get('cooldown_s'):
            self.sleep(float(cond['cooldown_s']))
        left, survivors = self.reap()
        waited = 0.0
        while True:
            c, bad = self.conditions()
            if survivors:
                bad.append('leftover processes could not be stopped: ' + '; '.join(r['cmd'][:60] for r in survivors[:3]))
            if not bad or waited >= float(cond['max_wait_s']):
                break
            self.sleep(30)
            waited += 30
            more, survivors = self.reap()
            left += more
        rec = {'type': 'attempt', **base, 'reaped_before': left,
               'conditions': {**{k2: v for k2, v in c.items() if k2 != 'therm'}, 'therm': c.get('therm', '')[:300], 'waited_s': waited}}
        if bad:
            rec.update({'skipped': True, 'conditions_ok': False, 'conditions_note': '; '.join(bad), 'exit': None, 'start': now(),
                        'timed_out': False, 'end': now(), 'log': '', 'log_sha256': '', 'values': {}, 'reaped': []})
            rec['outcome'], rec['reason'] = lv.classify(self.lab, cell, rec, '')[:2]
        else:
            name = re.sub(r'[^A-Za-z0-9._-]+', '_', f'{seq:04d}-{run_id}-{kind}-{"-".join(x for x in k if x)}.log')
            rec['start'] = now()
            # The start is on disk before the engine runs: an attempt that never finishes is still accounted for.
            self.ledger.add({'type': 'start', **base, 'start': rec['start'], 'log': name})
            rc, out, timed_out = self.x.sh(self.command(cell, kind, run_id), self.lab['timeout_s'])
            rec['end'] = now()
            path = os.path.join(self.logdir, name)
            header = (f'GBRUNNER session={self.session} attempt={seq} kind={kind} cell={"/".join(k)} '
                      f'start={rec["start"]} end={rec["end"]} exit={rc}\n')
            with open(path, 'w', encoding='utf-8') as f:
                f.write(lv.scrub(header + out))
            rec.update({'exit': rc, 'timed_out': timed_out, 'conditions_ok': True, 'log': name, 'log_sha256': lv.sha256_file(path)})
            text = open(path, encoding='utf-8', errors='replace').read()
            outcome, reason, vals = lv.classify(self.lab, cell, rec, text)
            rec['values'] = vals
            rec['outcome'], rec['reason'] = outcome, reason
            rec['reaped'], _ = self.reap()
        self.ledger.add(rec)
        self.say(f'#{seq} {kind} {"/".join(x for x in k if x)}: {rec["outcome"]}{" (" + rec["reason"][:100] + ")" if rec["reason"] else ""}')
        return rec

    def settle_interrupted(self):
        """Attempts that started but never finished (the Mac, the network or the pipeline broke off): each is recorded
        as an invalid attempt that used one of its cell's retries, with whatever log it left."""
        done = {r.get('seq') for r in self.ledger.recs if r.get('type') == 'attempt'}
        for r in [r for r in self.ledger.recs if r.get('type') == 'start' and r.get('seq') not in done]:
            path = os.path.join(self.logdir, r['log'])
            if not os.path.exists(path):
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(f'GBRUNNER session={self.session} attempt={r["seq"]} interrupted: no output was captured\n')
            self.ledger.add({'type': 'attempt', **{k: r[k] for k in ('seq', 'kind', 'round', 'cell', 'run_id')}, 'start': r['start'],
                             'end': now(), 'exit': None, 'timed_out': False, 'interrupted': True, 'conditions_ok': True,
                             'log': r['log'], 'log_sha256': lv.sha256_file(path), 'values': {},
                             'outcome': 'invalid', 'reason': 'interrupted (the run broke off before the attempt finished)'})

    def state(self):
        st_ = {k: {'ok': 0, 'timeout': 0, 'retries': 0, 'warm_ok': 0} for k in self.planned}
        for r in self.ledger.recs:
            if r.get('type') != 'attempt' or r['kind'] == 'smoke':
                continue
            k = lv.cell_key(r['cell'])
            if k not in st_:
                continue
            s = st_[k]
            if r['kind'] == 'warmup':
                if r['outcome'] == 'ok':
                    s['warm_ok'] += 1
                else:
                    s['retries'] += 1
            elif r['outcome'] == 'ok':
                s['ok'] += 1
            elif r['outcome'] == 'timeout':
                s['timeout'] += 1
            else:
                s['retries'] += 1
        return st_

    def past_deadline(self):
        return self.deadline is not None and time.time() > self.deadline

    # -- the session
    def run(self):
        recs = self.ledger.recs
        if any(r.get('type') == 'end' for r in recs):
            self.say('session already finished')
            return 0
        rc_info, mac_info = self.x.gbmac('info')
        reaped, survivors = self.reap()
        if survivors:
            raise RunnerError('leftover processes could not be stopped before measuring')
        rc, got, out = self.write_files()
        want = {p: hashlib.sha256(c.encode()).hexdigest() for p, c in (self.lab.get('files') or {}).items()}
        if rc != 0 or got != want:
            self.say(f'could not write the measurement scripts on the Mac (rc {rc}): {out[-400:]}')
            return 5
        rc, inputs, missing = self.hash_inputs()
        if missing:
            self.say(f'inputs missing: {missing[:10]}')
            return 3
        if rc != 0 or not inputs:
            self.say(f'inputs unreadable (rc {rc})')
            return 5
        wrong = self.check_expect()
        if wrong:
            self.say('the installed files are not the ones the plan names: ' + '; '.join(wrong[:6]))
            return 3
        if self.session == 2:
            # Before anything is measured: the same builds, models and prompts as session 1, and late enough.
            s1, err = lv.read_ledger(os.path.join(os.path.dirname(self.ledger.path), 'lab-ledger-s1.jsonl'))
            h1 = [r for r in s1 if r.get('type') == 'session']
            if err or not h1:
                self.say(f'session 1 ledger unusable: {err or "no session header"}')
                return 5
            in1, in2 = lv.cross_session_inputs(h1[-1].get('inputs')), lv.cross_session_inputs(inputs)
            if in1 != in2:
                diff = sorted(set(in1.items()) ^ set(in2.items()))[:4]
                self.say(f'the setup differs from session 1 (engine builds, models or prompts): {diff}')
                return 3
            gap_h = (time.time() - dt.datetime.fromisoformat(h1[-1]['started']).timestamp()) / 3600
            need_h = float((self.lab.get('replication') or {}).get('min_gap_hours', 12))
            if gap_h < need_h and os.environ.get('LAB_SAME_DAY_OK') != '1':
                self.say(f'only {gap_h:.1f} h since session 1; the plan needs {need_h:g} h')
                return 7
        heads = [r for r in recs if r.get('type') == 'session']
        counted = any(r.get('type') in ('attempt', 'start') and r.get('kind') != 'smoke' for r in recs)
        self.settle_interrupted()
        # A session resumes with the same inputs and the same code; before anything counts, other code (a runner fix)
        # records a new baseline instead, so every counted attempt of a session ran the code its header names.
        cur = runner_files()
        h = heads[-1] if heads else {}
        same_code = bool(heads) and (h['runner_files'] == cur if h.get('runner_files')
                                     else h.get('runner_sha256') == cur.get('labrun.py'))
        if heads and heads[-1].get('inputs') == inputs and (same_code or counted):
            self.ledger.add({'type': 'resume', 'at': now(), 'reaped': reaped, 'runner_files': runner_files()})
        elif heads and counted:
            self.say('engine builds, models or prompts changed after measuring began; refusing to resume this session')
            return 5
        else:
            # A new session, or a new baseline after a setup fix (allowed only before any warm-up or measured run).
            commit = subprocess.run(['git', '-C', os.path.dirname(HERE), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
            _, labenv = self.x.gbmac('labenv')
            self.ledger.add({'type': 'session', 'session': self.session, 'started': now(), 'plan_sha256': lv.sha256_file(self.plan_path),
                             'files': want, 'files_on_mac': got, 'inputs': inputs, 'expect_ok': True, 'commit': commit,
                             'rebaseline': bool(heads), 'runner_sha256': lv.sha256_file(os.path.abspath(__file__)),
                             'runner_files': runner_files(),
                             'mac_info': mac_info[-3000:], 'labenv': labenv[-6000:], 'reaped': reaped,
                             'planned': {'/'.join(k): v for k, v in self.planned.items()}})
        # The time budget counts from the session start, or from a resume (the Mac or the night broke off).
        t0 = max(dt.datetime.fromisoformat(r.get('started') or r.get('at')).timestamp()
                 for r in self.ledger.recs if r.get('type') in ('session', 'resume'))
        self.deadline = t0 + float(self.lab['max_hours']) * 3600
        lab = self.lab
        # Smoke: before anything counts (again on a resume that has not reached the warm-ups yet).
        if not any(r.get('type') == 'attempt' and r['kind'] != 'smoke' for r in self.ledger.recs):
            for spec in lab['smoke']:
                for c in lv.expand(spec):
                    c['measurement'] = c['measurement'] or 'main'
                    r = self.attempt(c, 'smoke')
                    if r['outcome'] != 'ok':
                        if self.smoke_only and r.get('skipped'):
                            # The design check: a busy Mac says nothing about the design.
                            self.say(f'smoke run not started: {r.get("conditions_note", "conditions not met")}')
                            return 5
                        self.say(f'smoke failed: {r["reason"]}')
                        return 3
        if self.smoke_only:
            self.ledger.add({'type': 'end', 'finished': now(), 'reason': 'smoke only', 'unrun': {}})
            self.say('smoke runs passed (smoke only: nothing measured)')
            return 0
        rng_base = int(lab['seed']) * 10 + self.session
        order = sorted(self.planned)
        random.Random(rng_base).shuffle(order)
        # Warm-ups.
        for k in order:
            while True:
                s = self.state()[k]
                if s['warm_ok'] >= lab['warmups'] or s['retries'] > lab['max_retries']:
                    break
                if self.past_deadline():
                    return self.finish('deadline')
                self.attempt(self.cells[k], 'warmup')
        # Measured rounds.
        rnd = max([r.get('round') or 0 for r in self.ledger.recs if r.get('type') == 'attempt' and r['kind'] == 'measure'] + [0])
        while True:
            st_ = self.state()
            need = [k for k in self.planned if st_[k]['warm_ok'] >= lab['warmups'] and st_[k]['ok'] + st_[k]['timeout'] < self.planned[k]
                    and st_[k]['retries'] <= lab['max_retries']]
            if not need:
                break
            rnd += 1
            todo = sorted(need)
            random.Random(rng_base * 1000 + rnd).shuffle(todo)
            for k in todo:
                s = self.state()[k]
                if s['ok'] + s['timeout'] >= self.planned[k] or s['retries'] > lab['max_retries']:
                    continue
                if self.past_deadline():
                    return self.finish('deadline')
                self.attempt(self.cells[k], 'measure', rnd)
        return self.finish('complete')

    def finish(self, reason):
        st_ = self.state()
        unrun = {'/'.join(k): self.planned[k] - s['ok'] - s['timeout'] for k, s in st_.items() if s['ok'] + s['timeout'] < self.planned[k]}
        # The same files at the end as at the start, and still the ones the plan names.
        rc, inputs_after, missing = self.hash_inputs()
        wrong_after = self.check_expect()
        _, labenv = self.x.gbmac('labenv')
        self.ledger.add({'type': 'end', 'finished': now(), 'reason': reason, 'unrun': unrun, 'labenv': labenv[-6000:],
                         'inputs_after': inputs_after if rc == 0 and not missing else {}, 'expect_after': wrong_after})
        try:
            import shutil
            shutil.copy(self.ledger.path, os.path.join(self.logdir, 'ledger.jsonl'))
        except OSError:
            pass
        self.say(f'session {self.session} {reason}; {sum(unrun.values())} planned run(s) not completed')
        return 0 if reason == 'complete' else 4


def main(argv):
    smoke = len(argv) == 5 and argv[0] == 'smoke'
    if not smoke and (len(argv) != 6 or argv[0] != 'run' or argv[2] not in ('1', '2')):
        print(__doc__)
        return 2
    if smoke:
        argv = [argv[0], argv[1], '1'] + argv[2:]
    plan = json.load(open(argv[1]))
    probs = lv.check_lab_plan(plan)
    if probs:
        print('labrun: the plan cannot be run:\n' + '\n'.join(probs))
        return 2
    try:
        return Runner(argv[1], int(argv[2]), argv[3], argv[4], argv[5], smoke_only=smoke).run()
    except RunnerError as e:
        print(f'labrun: {e}')
        return 5
    except (OSError, subprocess.SubprocessError) as e:
        print(f'labrun: {e}')
        return 5


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
