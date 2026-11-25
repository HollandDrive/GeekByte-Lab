#!/usr/bin/env python3
"""GeekByte Lab: the lab plan schema, verification of what the lab runner recorded, statistics and the generated
results. No LLM calls. Used by the publishing pipeline (check-plan, lab-verify, results-insert, results-check) and labrun.py.

The lab plan's `lab` block is data that the lab runner (labrun.py) executes and this module verifies:

  "lab": {
    "workdir": "gb-lab",                         folder under the session HOME on the Mac where the command runs
    "files": {"run.sh": "<content>", ...},       measurement scripts, frozen with the plan; the runner writes them itself
                                                 before measuring, and each must appear verbatim in ## Reproduce it
    "inputs": ["llama.cpp/llama-b12360", ...],   paths (globs) under HOME whose SHA-256 identifies what was measured
                                                 (engine builds, model files, prompts); session 2 must match session 1
    "cells": [{"model": "qwen36", "engine": ["mlx", "llama.cpp"], "config": "default", "length": ["4096", "131072"]}],
    "command": "./run.sh {model} {engine} {config} {length}",   run in workdir once per attempt; prints the metric lines
    "smoke": [{"model": "qwen36", "engine": "mlx", "config": "default", "length": "512"}],   quick runs before warm-ups
    "warmups": 1, "runs": 5, "seed": 20261114, "timeout_s": 1800, "max_retries": 2, "max_hours": 6,
    "conditions": {"max_load1": 3.0, "max_cpu_pct": 15, "max_other_rss_gb": 8, "no_thermal_warning": true,
                   "cooldown_s": 20, "max_wait_s": 900},
    "metrics": {"prompt_s": {"unit": "s", "better": "lower", "label": "prompt time",
                             "pattern": "^GBRESULT .*\\bprompt_s=(?P<value>[0-9.]+)",
                             "sample": "GBRESULT engine=mlx prompt_tokens=4096 prompt_s=0.695 prompt_tps=5891.310"}},
    "checks": [{"metric": "prompt_tokens", "op": "==", "value": "{length}"},
               {"metric": "cache_tokens", "op": "==", "value": 0, "engines": ["llama.cpp"]}],
    "primary": [{"metric": "prompt_s", "model": "qwen36", "length": ["4096", "131072"],
                 "a": "mlx default", "b": "llama.cpp default"}],
    "replication": {"runs": 5, "tolerance": 0.10},
    "timeout_is_result": false
  }
"""
import hashlib
import itertools
import json
import math
import os
import re
import statistics as st
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from labstats import ratio_ci  # noqa: E402

CELL_KEYS = ('measurement', 'model', 'engine', 'config', 'length')
SAFE = re.compile(r'^[A-Za-z0-9._:+=-]{1,80}$')
RELPATH = re.compile(r'^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$')
GLOB = re.compile(r'^[A-Za-z0-9._*?-]+(/[A-Za-z0-9._*?-]+)*$')
OPS = {'==': lambda a, b: math.isclose(a, b, rel_tol=0, abs_tol=1e-9), '<=': lambda a, b: a <= b + 1e-9,
       '>=': lambda a, b: a >= b - 1e-9, '<': lambda a, b: a < b, '>': lambda a, b: a > b}
SEP_MARGIN = 1.05
DEFAULT_CONDITIONS = {'max_load1': 3.0, 'max_cpu_pct': 15.0, 'max_other_rss_gb': 8.0, 'no_thermal_warning': True,
                      'cooldown_s': 20, 'max_wait_s': 900}
START, END = '<!-- generated:results:start -->', '<!-- generated:results:end -->'
# Private details: real addresses (not loopback or "any"), user folders (not /Users/Shared), and email addresses (a
# domain with a letter top-level label; not git@ remotes, not package@version specifiers).
SCRUB = [(re.compile(r'\b(?!127\.0\.0\.1\b)(?!0\.0\.0\.0\b)(?:\d{1,3}\.){3}\d{1,3}\b'), '<lab-ip>'),
         (re.compile(r'/Users/(?!Shared\b)[A-Za-z0-9._-]+'), '/Users/<lab>'),
         (re.compile(r'/home/[A-Za-z0-9._-]+'), '/home/<server>'),
         (re.compile(r'\b(?!git@)[\w.+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b'), '<email>')]


def scrub_words_path():
    """The local file of private words to redact (one per line, never published): LAB_SCRUB_WORDS, or the default."""
    return os.path.expanduser(os.environ.get('LAB_SCRUB_WORDS') or '~/.config/geekbyte/scrub-words')


def scrub_words_ready():
    """'' when the private-words file can be read and lists at least one word, else why not (publishing needs it,
    unless LAB_SCRUB_WORDS=none says there are none)."""
    if os.environ.get('LAB_SCRUB_WORDS') == 'none':
        return ''
    p = scrub_words_path()
    try:
        with open(p, encoding='utf-8') as f:
            ok = any(w.strip() for w in f)
    except (OSError, UnicodeDecodeError) as e:
        return f'the private-words file ({p}) cannot be read: {e.__class__.__name__}'
    return '' if ok else f'the private-words file ({p}) is empty'


def code_private(text):
    """Lines of published code that hold a private detail. Two things are not private: the documented public contact
    address, and a home folder built under a shell variable ("$d/home/.cache", "${d}/home"), which is the test
    account's temporary HOME."""
    t = text.replace('editor@geekbyte.com', 'editor-at-geekbyte')
    t = re.sub(r'(\$\{?[A-Za-z0-9_]+\}?)/(home|Users)/', r'\1/\2_/', t)
    return [i for i, (a, b) in enumerate(zip(t.splitlines(), scrub(t).splitlines()), 1) if a != b]


def _scrub_words():
    """Private words from scrub_words_path(); none when the file is missing (publishing checks that it exists)."""
    try:
        ws = [w.strip() for w in open(scrub_words_path(), encoding='utf-8') if w.strip()]
    except OSError:
        ws = []
    return [re.compile(r'\b' + re.escape(w) + r'\b', re.I) for w in ws]


_WORDS = None


def scrub(text):
    """Remove addresses, user paths, emails and private words. The lab runner applies it as it writes logs and ledger
    records, so the published copies are the hashed originals."""
    global _WORDS
    if _WORDS is None:
        _WORDS = _scrub_words()
    for rx, rep in SCRUB:
        text = rx.sub(rep, text)
    for rx in _WORDS:
        text = rx.sub('<redacted>', text)
    return text


# ---------------------------------------------------------------------------------------------------- plan schema

def expand(spec, keys=CELL_KEYS):
    """Every combination of a spec whose fields may be lists (cartesian product); missing fields are ''."""
    lists = [spec.get(k) if isinstance(spec.get(k), list) else [spec.get(k)] for k in keys]
    return [dict(zip(keys, ('' if x is None else str(x).strip() for x in combo))) for combo in itertools.product(*lists)]


def cell_key(c):
    return tuple((c.get(k) or ('main' if k == 'measurement' else '')) for k in CELL_KEYS)


def label(c):
    return f"{c['engine']} {c['config']}".strip()


def lab_conf(plan):
    """The plan's lab block with defaults filled in (does not validate)."""
    lab = dict(plan.get('lab') or {})
    lab.setdefault('warmups', 1)
    lab.setdefault('runs', 5)
    lab.setdefault('max_retries', 2)
    lab.setdefault('timeout_s', 1800)
    lab.setdefault('max_hours', 6)
    lab.setdefault('files', {})
    lab.setdefault('checks', [])
    lab.setdefault('smoke', [])
    lab.setdefault('timeout_is_result', False)
    lab['conditions'] = {**DEFAULT_CONDITIONS, **(lab.get('conditions') or {})}
    return lab


def cells_of(lab, session=1):
    """{cell key: planned measured runs} for a session (session 2: the cells behind the primary comparisons)."""
    out = {}
    for spec in lab.get('cells') or []:
        for c in expand(spec):
            k = cell_key(c)
            out[k] = int(spec.get('runs') or lab['runs'])
    if session == 2:
        rep = lab.get('replication') or {}
        keep = set()
        for p in primaries(lab):
            keep |= {p['ka'], p['kb']}
        out = {k: int(rep.get('runs') or v) for k, v in out.items() if k in keep}
    return out


def primaries(lab):
    """Expanded primary comparisons, each with the cell keys of its two sides."""
    cells = {cell_key(c): c for spec in lab.get('cells') or [] for c in expand(spec)}
    by_label = {}
    for k, c in cells.items():
        by_label.setdefault((k[0], c['model'], c['length'], label(c)), []).append(k)
    out = []
    for spec in lab.get('primary') or []:
        for c in expand(spec, ('measurement', 'model', 'length', 'metric', 'a', 'b')):
            meas = c['measurement'] or 'main'
            ka = by_label.get((meas, c['model'], c['length'], c['a']), [])
            kb = by_label.get((meas, c['model'], c['length'], c['b']), [])
            out.append({'measurement': meas, 'model': c['model'], 'length': c['length'], 'metric': c['metric'],
                        'a': c['a'], 'b': c['b'], 'ka': ka[0] if len(ka) == 1 else None,
                        'kb': kb[0] if len(kb) == 1 else None, 'na': len(ka), 'nb': len(kb)})
    return out


def patterns_for(metric, engine):
    p = metric.get('pattern')
    if isinstance(p, dict):
        return p.get(engine)
    return p


def metric_applies(metric, engine):
    engs = metric.get('engines')
    if engs and engine not in engs:
        return False
    return patterns_for(metric, engine) is not None


def _norm_text(s):
    return '\n'.join(l.rstrip() for l in s.strip('\n').splitlines())


def code_blocks(text):
    return [m.group(1) for m in re.finditer(r'^```[^\n]*\n(.*?)^```', text, re.M | re.S)]


def check_lab_plan(plan, article_text=None, mac_available=True):
    """Problems with a lab plan's `lab` block (empty list when it can be run and verified as written)."""
    probs = []
    raw = plan.get('lab')
    if not isinstance(raw, dict):
        return ['lab plan has no "lab" block (the runner needs cells, command, metrics, primary and replication)']
    lab = lab_conf(plan)
    if not isinstance(lab.get('workdir'), str) or not RELPATH.match(lab['workdir']) or '..' in lab['workdir']:
        probs.append('lab.workdir must be a plain relative folder under HOME (for example "gb-lab")')
    files = lab.get('files')
    if not isinstance(files, dict):
        probs.append('lab.files must be an object {relative path: content}')
        files = {}
    total = 0
    # A file that is also another file's folder ("a" and "a/b") cannot be written: refuse it here, not on the Mac.
    names = {str(p).strip('/') for p in files}
    for p in sorted(names):
        parts = p.split('/')
        for i in range(1, len(parts)):
            if '/'.join(parts[:i]) in names:
                probs.append(f'lab.files: {"/".join(parts[:i])!r} is both a file and the folder of {p!r}')
    for p, content in files.items():
        if not RELPATH.match(str(p)) or '..' in str(p) or any(c in ('', '.') for c in str(p).split('/')):
            probs.append(f'lab.files: bad path {p!r} (plain relative path, no "." or empty parts)')
        if not isinstance(content, str) or not content.strip():
            probs.append(f'lab.files: {p} has no content')
            continue
        total += len(content.encode())
        if article_text is not None:
            body = _norm_text(content)
            if not any(body in _norm_text(b) for b in code_blocks(article_text)):
                probs.append(f'lab.files: {p} is not printed verbatim in a code block of the report (readers must get the exact script that ran)')
    if total > 400_000:
        probs.append('lab.files: over 400 KB in all; keep the scripts short')
    ins = lab.get('inputs')
    if not isinstance(ins, list) or not ins or not all(isinstance(g, str) and GLOB.match(g) and '..' not in g for g in ins):
        probs.append('lab.inputs must list the engine builds, model files and prompts as plain relative paths or globs under HOME')
    exp = lab.get('expect')
    if not isinstance(exp, list) or not exp:
        probs.append('lab.expect must pre-register official identities of what is measured: model files and release '
                     'archives by their published SHA-256, Python packages by version (checked against their RECORD hashes)')
        exp = []
    for e in exp:
        if not isinstance(e, dict):
            probs.append(f'lab.expect: bad entry {e!r}')
        elif 'path' in e:
            if not (isinstance(e['path'], str) and RELPATH.match(e['path']) and '..' not in e['path'] and re.fullmatch(r'[0-9a-f]{64}', str(e.get('sha256', '')))):
                probs.append(f'lab.expect: a file entry needs a plain relative path and a 64-hex sha256: {e}')
        elif 'archive' in e:
            if not (isinstance(e['archive'], str) and RELPATH.match(e['archive']) and re.fullmatch(r'[0-9a-f]{64}', str(e.get('sha256', '')))
                    and isinstance(e.get('members', {}), dict) and all(RELPATH.match(str(a)) and RELPATH.match(str(b)) for a, b in e.get('members', {}).items())):
                probs.append(f'lab.expect: an archive entry needs a relative path, a 64-hex sha256 and members {{installed path: path in archive}}: {e}')
        elif 'python' in e:
            if not (isinstance(e['python'], str) and RELPATH.match(e['python']) and isinstance(e.get('packages'), dict) and e['packages']
                    and all(re.fullmatch(r'[A-Za-z0-9._-]+', str(n)) and re.fullmatch(r'[A-Za-z0-9.+!_-]+', str(v)) for n, v in e['packages'].items())):
                probs.append(f'lab.expect: a python entry needs the interpreter path and {{package: version}}: {e}')
        else:
            probs.append(f'lab.expect: entry needs path, archive or python: {e}')
    for k, lo, hi in (('warmups', 1, 3), ('runs', 3, 20), ('max_retries', 0, 5), ('timeout_s', 30, 7200)):
        if not isinstance(lab.get(k), int) or not lo <= lab[k] <= hi:
            probs.append(f'lab.{k} must be a whole number from {lo} to {hi}')
    if not isinstance(lab.get('seed'), int):
        probs.append('lab.seed must be a whole number (the run order is a seeded shuffle per round, fixed in advance)')
    if not isinstance(lab.get('max_hours'), (int, float)) or not 0.2 <= lab['max_hours'] <= 7:
        probs.append('lab.max_hours must be from 0.2 to 7 (one night)')
    cond = lab['conditions']
    for k in ('max_load1', 'max_cpu_pct', 'max_other_rss_gb', 'cooldown_s', 'max_wait_s'):
        if not isinstance(cond.get(k), (int, float)) or isinstance(cond.get(k), bool) or not math.isfinite(cond[k]) or cond[k] < 0:
            probs.append(f'lab.conditions.{k} must be a non-negative number')
    cmd = lab.get('command')
    if not isinstance(cmd, str) or not cmd.strip():
        probs.append('lab.command is missing')
        cmd = ''
    bad_ph = sorted(set(re.findall(r'\{([^{}]*)\}', cmd)) - set(CELL_KEYS) - {'run_id', 'kind', 'session'})
    if bad_ph:
        probs.append(f'lab.command uses unknown placeholders: {bad_ph}')
    else:
        try:
            cmd.format(**{k: 'x' for k in CELL_KEYS}, run_id='x', kind='x', session='1')
        except (KeyError, ValueError, IndexError) as e:
            probs.append(f'lab.command cannot be filled in ({e}); write a literal brace as {{{{ or }}}}')
    metrics = lab.get('metrics')
    if not isinstance(metrics, dict) or not metrics:
        probs.append('lab.metrics is missing')
        metrics = {}
    for name, m in metrics.items():
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,40}', name):
            probs.append(f'metric name {name!r}: use lowercase letters, digits and _')
        if not isinstance(m, dict) or not m.get('unit') or m.get('better') not in ('lower', 'higher', 'none'):
            probs.append(f'metric {name}: needs "unit" and "better" (lower, higher or none)')
            continue
        pats = m.get('pattern') if isinstance(m.get('pattern'), dict) else {'*': m.get('pattern')}
        samples = m.get('sample') if isinstance(m.get('sample'), dict) else {e: m.get('sample') for e in pats}
        for eng, pat in pats.items():
            try:
                rx = re.compile(pat)
            except (re.error, TypeError) as e:
                probs.append(f'metric {name} ({eng}): pattern is not a valid regex: {e}')
                continue
            if 'value' not in rx.groupindex:
                probs.append(f'metric {name} ({eng}): pattern has no (?P<value>...) group')
                continue
            smp = samples.get(eng)
            if not isinstance(smp, str) or not smp:
                probs.append(f'metric {name} ({eng}): give "sample", a real output line the pattern must read')
                continue
            hits = [x for x in smp.splitlines() if rx.search(x)]
            if len(hits) != 1:
                probs.append(f'metric {name} ({eng}): the pattern matches {len(hits)} line(s) of its sample, not exactly one')
                continue
            try:
                float(rx.search(hits[0]).group('value'))
            except (TypeError, ValueError):
                probs.append(f'metric {name} ({eng}): the pattern reads a value from its sample that is not a number')
    if not lab['checks']:
        probs.append('lab.checks is empty: register at least the checks that make a run invalid (for example the prompt tokens processed)')
    for ch in lab['checks']:
        if not isinstance(ch, dict) or ch.get('metric') not in metrics or ch.get('op') not in OPS or 'value' not in ch:
            probs.append(f'lab.checks: each check needs a known metric, op (== <= >= < >) and value: {ch}')
            continue
        v = ch['value']
        if isinstance(v, str):
            ph = set(re.findall(r'\{([^{}]*)\}', v))
            if not ph or ph - set(CELL_KEYS) or re.sub(r'\{[^{}]*\}', '', v).strip():
                probs.append(f'lab.checks: value must be a number or exactly one cell field such as "{{length}}": {ch}')
        elif isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            probs.append(f'lab.checks: value must be a finite number: {ch}')
    cells = {}
    for spec in lab.get('cells') or []:
        if not isinstance(spec, dict) or set(spec) - set(CELL_KEYS) - {'runs', 'est_run_minutes'}:
            probs.append(f'lab.cells: unknown fields in {spec}')
            continue
        r = int(spec.get('runs') or lab.get('runs') or 0)
        if r < 3:
            probs.append(f'lab.cells: {r} runs; at least 3 per cell (5 unless one run takes over five minutes): {spec}')
        elif r < 5 and not (isinstance(spec.get('est_run_minutes'), (int, float)) and spec['est_run_minutes'] > 5):
            probs.append(f'lab.cells: {r} runs is allowed only where one run takes over five minutes (give est_run_minutes): {spec}')
        for c in expand(spec):
            for k in ('model', 'engine', 'config', 'length'):
                if not c[k]:
                    probs.append(f'lab.cells: a cell has no {k}: {spec}')
            if any(v and not SAFE.match(v) for v in c.values()):
                probs.append(f'lab.cells: values may use only letters, digits and ._:+=- (they are passed to the command): {c}')
            k = cell_key(c)
            if k in cells:
                probs.append(f'lab.cells: cell listed twice: {" / ".join(k)}')
            cells[k] = c
    if not cells:
        probs.append('lab.cells lists no cells')
    labels_by_eng = {}
    for c in cells.values():
        labels_by_eng.setdefault(c['engine'], set()).add(c['config'])
    for name, m in metrics.items():
        if isinstance(m, dict) and isinstance(m.get('pattern'), dict):
            for eng in labels_by_eng:
                if eng not in m['pattern'] and not (m.get('engines') and eng not in m['engines']):
                    probs.append(f'metric {name}: no pattern for engine {eng!r} (engine names must match lab.cells exactly)')
    smoke = lab.get('smoke')
    if not isinstance(smoke, list) or not smoke:
        probs.append('lab.smoke must list at least one quick cell to run before the warm-ups (it catches a broken setup in minutes)')
    else:
        for spec in smoke:
            for c in expand(spec):
                if not all(c[k] for k in ('model', 'engine', 'config', 'length')) or any(v and not SAFE.match(v) for v in c.values()):
                    probs.append(f'lab.smoke: bad cell {c}')
    prim = primaries(lab)
    if not prim:
        probs.append('lab.primary lists no pre-registered comparison')
    if len(prim) > 12:
        probs.append(f'lab.primary expands to {len(prim)} comparisons; keep the pre-registered ones few (the title and short answer rest on them)')
    for p in prim:
        where = f"{p['measurement']} / {p['model']} / {p['length']} / {p['metric']}: {p['a']} vs {p['b']}"
        if p['metric'] not in metrics:
            probs.append(f'primary {where}: unknown metric')
        if p['na'] != 1 or p['nb'] != 1:
            probs.append(f'primary {where}: each side must name exactly one cell as "<engine> <config>" (found {p["na"]} and {p["nb"]})')
        elif p['metric'] in metrics:
            m = metrics[p['metric']]
            if not (metric_applies(m, cells[p['ka']]['engine']) and metric_applies(m, cells[p['kb']]['engine'])):
                probs.append(f'primary {where}: the metric is not read for both engines')
        if p['a'] == p['b']:
            probs.append(f'primary {where}: compares a cell with itself')
    rep = lab.get('replication')
    if not isinstance(rep, dict):
        probs.append('lab.replication is required: {"runs": N, "tolerance": 0.10} (the second session on a later day)')
    else:
        if not isinstance(rep.get('runs', lab['runs']), int) or rep.get('runs', lab['runs']) < 3:
            probs.append('lab.replication.runs must be at least 3')
        g = rep.get('min_gap_hours', 12)
        if not isinstance(g, (int, float)) or isinstance(g, bool) or not 6 <= g <= 240:
            probs.append('lab.replication.min_gap_hours must be from 6 to 240 (the second session is on a later day)')
        t = rep.get('tolerance', 0.10)
        if not isinstance(t, (int, float)) or not 0 < t <= 0.5:
            probs.append('lab.replication.tolerance must be between 0 and 0.5 (the largest change in a ratio that still counts as repeated)')
    # The plan is published byte for byte with the report, so it must not contain anything the scrubber would remove.
    raw_plan = json.dumps(plan, ensure_ascii=False)
    if scrub(raw_plan) != raw_plan:
        probs.append('the plan contains a private detail (an address, a user folder, an email or a private word); '
                     'use ~ paths and placeholders, because the plan is published as it is')
    n_att = sum(r + lab['warmups'] for r in cells_of(lab).values()) if cells else 0
    if n_att > 400:
        probs.append(f'{n_att} runs in session 1; too many for one night')
    return probs


# ---------------------------------------------------------------------------------------------------- ledger

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def chain_hash(prev, body):
    body = {k: v for k, v in body.items() if k not in ('hash', 'prev')}
    body['prev'] = prev
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()


def cross_session_inputs(inputs):
    """Inputs as compared between session 1 and session 2. pip's *.dist-info/RECORD files are left out: they store
    hashes of console scripts whose first line names the session folder, which is new each session, and every file
    a RECORD lists is fingerprinted on its own anyway. Within one session (start against end) they still count."""
    return {k: v for k, v in (inputs or {}).items() if not k.endswith('.dist-info/RECORD')}


def read_ledger(path):
    """(records, problem or None). Each record carries prev and hash (SHA-256 over prev and its content)."""
    recs = []
    if not os.path.exists(path):
        return [], f'no ledger {os.path.basename(path)}'
    prev = '0' * 64
    for i, line in enumerate(open(path, encoding='utf-8'), 1):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except ValueError:
            return recs, f'ledger line {i} is not JSON'
        if r.get('prev') != prev or chain_hash(prev, r) != r.get('hash'):
            return recs, f'ledger record {i}: hash chain broken (edited, removed or reordered)'
        prev = r['hash']
        recs.append(r)
    return recs, None


def extract(lab, engine, text):
    """{metric: value} read with the plan's patterns (each must match exactly one line), and problems."""
    vals, probs = {}, []
    lines = text.splitlines()
    for name, m in (lab.get('metrics') or {}).items():
        if not metric_applies(m, engine):
            continue
        rx = re.compile(patterns_for(m, engine))
        hits = [rx.search(l) for l in lines]
        hits = [h for h in hits if h]
        if len(hits) != 1:
            probs.append(f'{name}: {len(hits)} matching lines (need exactly 1)')
            continue
        try:
            vals[name] = float(hits[0].group('value'))
        except (TypeError, ValueError):
            probs.append(f'{name}: not a number: {hits[0].group("value")!r}')
    return vals, probs


def run_checks(lab, cell, vals):
    bad = []
    for ch in lab.get('checks') or []:
        if ch.get('engines') and cell['engine'] not in ch['engines']:
            continue
        if ch['metric'] not in vals:
            continue
        want = ch['value']
        if isinstance(want, str):
            want = want.format(**cell)
        try:
            want = float(want)
        except (TypeError, ValueError):
            bad.append(f'check {ch["metric"]} {ch["op"]} {ch["value"]}: not a number after substitution')
            continue
        if not OPS[ch['op']](vals[ch['metric']], want):
            bad.append(f'{ch["metric"]} = {vals[ch["metric"]]:g}, needs {ch["op"]} {want:g}')
    return bad


def classify(lab, cell, att, text):
    """The outcome of one attempt from its record and its log: ok, timeout, failed or invalid (with reasons)."""
    if att.get('skipped'):
        return 'invalid', 'conditions not met: ' + str(att.get('conditions_note', '')), {}
    if att.get('interrupted'):
        return 'invalid', 'interrupted (the run broke off before the attempt finished)', {}
    vals, probs = extract(lab, cell['engine'], text) if text is not None else ({}, ['log missing'])
    if att.get('timed_out'):
        return 'timeout', f'stopped after {lab["timeout_s"]} s', vals
    if att.get('exit') != 0:
        return 'failed', f'exit {att.get("exit")}', vals
    if not att.get('conditions_ok', True):
        return 'invalid', 'conditions not met: ' + str(att.get('conditions_note', '')), vals
    if probs:
        return 'invalid', '; '.join(probs), vals
    bad = run_checks(lab, cell, vals)
    if bad:
        return 'invalid', '; '.join(bad), vals
    return 'ok', '', vals


# ---------------------------------------------------------------------------------------------------- verification

def _fmt(x):
    a = abs(x)
    return f'{x:.0f}' if a >= 1000 else f'{x:.1f}' if a >= 10 else f'{x:.2f}' if a >= 1 else f'{x:.3f}'


def verify_session(plan, plan_path, rundir, evid, session):
    """Verify one session's ledger against the plan and the runner's logs. Returns a dict with attempts, problems,
    the header and per-cell accounting."""
    lab = lab_conf(plan)
    probs, notes = [], []
    path = os.path.join(evid, f'lab-ledger-s{session}.jsonl')
    recs, err = read_ledger(path)
    if err:
        probs.append(f'session {session}: {err}')
    heads = [i for i, r in enumerate(recs) if r.get('type') == 'session']
    head = recs[heads[-1]] if heads else None
    end = next((r for r in recs if r.get('type') == 'end'), None)
    atts = [r for r in recs if r.get('type') == 'attempt']
    # A new baseline (after a setup fix) is allowed only before anything counted: every warm-up and measured attempt
    # must come after the last session header.
    if heads and any(r.get('type') in ('attempt', 'start') and r.get('kind') != 'smoke' for r in recs[:heads[-1]]):
        probs.append(f'session {session}: a new baseline was recorded after warm-ups or measured runs had started')
    started = {r.get('seq') for r in recs if r.get('type') == 'start'}
    finished = {r.get('seq') for r in atts}
    for q in sorted(started - finished, key=lambda x: x or 0):
        probs.append(f'session {session}: attempt {q} started but was never recorded as finished')
    out = {'session': session, 'problems': probs, 'notes': notes, 'attempts': [], 'header': head or {}, 'end': end or {},
           'cells': {}, 'complete': False}
    if not head:
        probs.append(f'session {session}: the ledger has no session header')
        return out
    if head.get('plan_sha256') != sha256_file(plan_path):
        probs.append(f'session {session}: the plan changed after it was frozen (SHA-256 differs from the one the runner used)')
    want_files = {p: hashlib.sha256(c.encode()).hexdigest() for p, c in (lab.get('files') or {}).items()}
    if head.get('files') != want_files:
        probs.append(f'session {session}: the measurement scripts the runner wrote differ from the plan\'s lab.files')
    if head.get('files_on_mac') != want_files:
        probs.append(f'session {session}: the scripts on the Mac did not hash to the plan\'s lab.files before measuring')
    if not end:
        probs.append(f'session {session}: the runner did not finish (no end record); resume it or re-measure')
    else:
        # Exactly the fingerprints of the last start (the header, or a resume in a new Mac folder), and every file the
        # same as when the session began (pip RECORD files aside, which name the folder: see cross_session_inputs).
        last = next((r['inputs'] for r in reversed(recs[heads[-1] + 1:]) if r.get('type') == 'resume' and r.get('inputs')), head.get('inputs'))
        after = end.get('inputs_after')
        if after != last or cross_session_inputs(after) != cross_session_inputs(head.get('inputs')):
            ref = last if after != last else head.get('inputs')
            changed = sorted(set((ref or {}).items()) ^ set((after or {}).items()))[:4]
            probs.append(f'session {session}: engine builds, models or prompts changed during the session: {changed}')
        if end.get('expect_after'):
            probs.append(f'session {session}: at the end the installed files no longer matched lab.expect: {end["expect_after"][:3]}')
    if not head.get('expect_ok'):
        probs.append(f'session {session}: the runner did not confirm lab.expect before measuring')
    planned = cells_of(lab, session)
    state = {k: {'ok': [], 'timeout': 0, 'retries': 0, 'warm_ok': 0, 'other': []} for k in planned}
    prev_cell = None
    seqs = set()
    for a in atts:
        cell = a.get('cell') or {}
        k = cell_key(cell)
        if a.get('seq') in seqs:
            probs.append(f'session {session}: attempt number {a.get("seq")} appears twice')
        seqs.add(a.get('seq'))
        logp = os.path.join(rundir, 'raw', f'runner-s{session}', a.get('log', ''))
        text = None
        if a.get('skipped'):
            text = ''
        elif not a.get('log') or not os.path.isfile(logp):
            probs.append(f'session {session} attempt {a.get("seq")}: log {a.get("log")} missing')
        elif sha256_file(logp) != a.get('log_sha256'):
            probs.append(f'session {session} attempt {a.get("seq")}: log changed after the runner wrote it')
        else:
            text = open(logp, encoding='utf-8', errors='replace').read()
        kind = a.get('kind')
        if kind not in ('smoke', 'warmup', 'measure'):
            probs.append(f'session {session} attempt {a.get("seq")}: unknown kind {kind!r}')
            continue
        if kind != 'smoke' and k not in planned:
            probs.append(f'session {session} attempt {a.get("seq")}: cell {" / ".join(k)} is not in this session\'s plan')
            continue
        outcome, reason, vals = classify(lab, cell, a, text) if text is not None else (a.get('outcome'), 'log unusable', {})
        if text is not None and (outcome != a.get('outcome') or any(not math.isclose(vals.get(m, float('nan')), v, rel_tol=1e-12)
                                                                    for m, v in (a.get('values') or {}).items())):
            probs.append(f'session {session} attempt {a.get("seq")}: the ledger says {a.get("outcome")} but its log gives {outcome} ({reason})')
        rec = {'seq': a.get('seq'), 'kind': kind, 'cell': k, 'outcome': outcome, 'reason': reason, 'values': vals,
               'start': a.get('start'), 'end': a.get('end'), 'round': a.get('round'), 'log': a.get('log'),
               'conditions': a.get('conditions') or {}}
        out['attempts'].append(rec)
        if kind == 'smoke':
            continue
        s = state[k]
        if kind == 'warmup':
            s['warm_ok'] += outcome == 'ok'
            if outcome != 'ok':
                s['retries'] += 1
            continue
        if s['warm_ok'] < lab['warmups']:
            probs.append(f'session {session} attempt {a.get("seq")}: measured before its warm-up(s) completed: {" / ".join(k)}')
        if outcome == 'ok':
            s['ok'].append(rec)
        elif outcome == 'timeout':
            s['timeout'] += 1
        else:
            s['retries'] += 1
            s['other'].append(outcome)
        if prev_cell == (k, a.get('round')):
            probs.append(f'session {session} attempt {a.get("seq")}: the same cell twice in one round (the order was not interleaved)')
        prev_cell = (k, a.get('round'))
    for k, need in planned.items():
        s = state[k]
        got = len(s['ok']) + s['timeout']
        if got > need:
            probs.append(f'session {session} {" / ".join(k)}: {got} measured runs but {need} planned')
        if s['retries'] > lab['max_retries'] + 1:
            probs.append(f'session {session} {" / ".join(k)}: {s["retries"]} failed or invalid attempts; the runner stops after '
                         f'{lab["max_retries"] + 1} (the first failure and {lab["max_retries"]} retries)')
        s['need'] = need
        s['not_run'] = max(0, need - got)
        s['status'] = ('complete' if len(s['ok']) == need else
                       'timeouts' if s['timeout'] == need and not s['ok'] else
                       'mixed' if s['timeout'] and len(s['ok']) + s['timeout'] == need else 'incomplete')
    out['cells'] = state
    out['complete'] = bool(end) and not probs
    return out


def group_stats(lab, sess):
    """{(cell key, metric): (n, mean, sd, min, max, values)} from the ok measured runs."""
    stats = {}
    for k, s in sess['cells'].items():
        if not s['ok']:
            continue
        for m in lab['metrics']:
            vals = [r['values'][m] for r in s['ok'] if m in r['values']]
            if not vals:
                continue
            n, mean = len(vals), st.mean(vals)
            sd = st.stdev(vals) if n > 1 else 0.0
            stats[(k, m)] = (n, mean, sd, min(vals), max(vals), vals)
    return stats


def compare(lab, stats, cells, p):
    """One primary comparison in one session: dict with status, ratio, CI and verdict."""
    sa, sb = cells.get(p['ka']), cells.get(p['kb'])
    if not sa or not sb:
        return {'status': 'not measured'}
    if (sa['status'] == 'timeouts' and sb['status'] in ('timeouts', 'complete')) or (sb['status'] == 'timeouts' and sa['status'] == 'complete'):
        return {'status': 'timeouts' if lab.get('timeout_is_result') else 'incomplete',
                'note': 'every planned run of ' + ('both sides' if sa['status'] == sb['status'] else 'one side') + ' ran past its time limit',
                'sides': (sa['status'], sb['status'])}
    if sa['status'] != 'complete' or sb['status'] != 'complete':
        return {'status': 'incomplete'}
    va, vb = stats.get((p['ka'], p['metric'])), stats.get((p['kb'], p['metric']))
    if not va or not vb or not va[1] or not vb[1]:
        return {'status': 'incomplete', 'note': 'no values for this metric'}
    ratio = va[1] / vb[1]
    ci = ratio_ci(va[5], vb[5])
    ci_rev = ratio_ci(vb[5], va[5])  # computed directly: inverting endpoints is wrong when an interval reaches zero
    if ci is not None and ci[0] <= 0:
        ci = None  # an interval that reaches zero or below is unbounded for a ratio of positive quantities
    if ci_rev is not None and ci_rev[0] <= 0:
        ci_rev = None
    if ci is None:
        verdict = 'no'
    else:
        verdict = 'yes' if (ci[0] > SEP_MARGIN or ci[1] < 1 / SEP_MARGIN) else 'no'
    return {'status': 'complete', 'ratio': ratio, 'ci': ci, 'ci_rev': ci_rev, 'separated': verdict, 'mean_a': va[1], 'mean_b': vb[1],
            'n_a': va[0], 'n_b': vb[0]}


def _usable(c):
    """A complete comparison with a finite positive ratio and a bounded interval (0 < low <= high)."""
    ci = c.get('ci')
    return (c.get('status') == 'complete' and isinstance(c.get('ratio'), (int, float)) and math.isfinite(c['ratio']) and c['ratio'] > 0
            and bool(ci) and all(math.isfinite(x) for x in ci) and 0 < ci[0] <= ci[1])


def repeated(c1, c2, tol):
    """Replication rule (24 November 2026): both days usable, the same Separated verdict, the ratio within the tolerance
    of the first day's, and, when the first day separated, the same direction. A comparison neither day separated
    claims no direction, so the side of 1 its ratio lands on is not compared (it is noise, and 1.000 has no side);
    it is reported only as "neither session separated a difference", never as equivalence."""
    if not (_usable(c1) and _usable(c2)) or c1['separated'] != c2['separated'] or abs(c2['ratio'] / c1['ratio'] - 1) > tol:
        return False
    return c1['separated'] == 'no' or (c1['ratio'] > 1) == (c2['ratio'] > 1)


def _cell_txt(k):
    return ' / '.join(x for x in k if x)


def _claim(lab, p, c1, c2):
    m = lab['metrics'][p['metric']]
    unit = m['unit']
    name = m.get('label') or p['metric']

    def v(x):
        s = f'{_fmt(x)} {unit}'
        if unit == 's' and x >= 120:
            s += f' ({_fmt(x / 60)} min)'
        return s
    head = f"- {p['model']}, {p['length']}, {name}: {p['a']} {v(c1['mean_a'])} against {p['b']} {v(c1['mean_b'])}"
    if c1.get('ci'):
        r, lo, hi = c1['ratio'], c1['ci'][0], c1['ci'][1]
        rev = f"(95% CI {c1['ci_rev'][0]:.3f} to {c1['ci_rev'][1]:.3f})" if c1.get('ci_rev') else '(95% CI unbounded)'
        head += (f". {p['a']} / {p['b']} = {r:.3f} (95% CI {lo:.3f} to {hi:.3f}); "
                 f"{p['b']} / {p['a']} = {1 / r:.3f} {rev}")
        if c1['separated'] == 'yes' and m.get('better') in ('lower', 'higher'):
            a_wins = (r < 1) == (m['better'] == 'lower')
            win, lose = (p['a'], p['b']) if a_wins else (p['b'], p['a'])
            head += (f". Separated: yes; {win} is better ({m['better']} {name}) by a factor of {max(r, 1 / r):.2f} "
                     f"against {lose}")
        elif c1['separated'] == 'yes':
            head += '. Separated: yes'
        else:
            head += f". Separated: no (no difference we could separate in {min(c1['n_a'], c1['n_b'])} runs)"
    else:
        head += '. No interval (too few runs or too noisy): no difference we could separate'
    if c2 is not None:
        if c2.get('status') == 'complete' and c2.get('ci'):
            head += f". Second day: {c2['ratio']:.3f} (95% CI {c2['ci'][0]:.3f} to {c2['ci'][1]:.3f}), separated {c2['separated']}"
        else:
            head += f". Second day: {c2.get('status')}"
    return head + '.'


def lab_verify(plan_path, rundir, derived_out, verdict_out, evid, slug=None, sessions='1'):
    """Verify the runner's record of one or both sessions, compute the statistics, and write the derived figures,
    the generated data files and a structured verdict. Exit 1 when anything must hold the report."""
    plan = json.load(open(plan_path))
    lab = lab_conf(plan)
    slug = slug or plan.get('slug') or 'lab'
    want2 = sessions == '2'
    s1 = verify_session(plan, plan_path, rundir, evid, 1)
    s2 = verify_session(plan, plan_path, rundir, evid, 2) if want2 else None
    problems = list(s1['problems']) + (s2['problems'] if s2 else [])
    notes = list(s1['notes']) + (s2['notes'] if s2 else [])
    if s2 and s1['header'].get('started') and s2['header'].get('started'):
        import datetime as _dt
        gap = (_dt.datetime.fromisoformat(s2['header']['started']) - _dt.datetime.fromisoformat(s1['header']['started'])).total_seconds() / 3600
        need_gap = float((lab.get('replication') or {}).get('min_gap_hours', 12))
        if gap < need_gap:
            if os.environ.get('LAB_SAME_DAY_OK') == '1':
                notes.append(f'session 2 started {gap:.1f} h after session 1, less than the plan\'s {need_gap:g} h (allowed for a shakedown; '
                             f'the report must not call it a later day)')
            else:
                problems.append(f'session 2 started {gap:.1f} h after session 1; the plan needs at least {need_gap:g} h')
    in1 = cross_session_inputs(s1['header'].get('inputs'))
    in2 = cross_session_inputs(s2['header'].get('inputs')) if s2 else {}
    if s2 and in1 and in2 != in1:
        diff = sorted(set(in1.items()) ^ set(in2.items()))[:6]
        problems.append(f'session 2 measured different engine builds, models or prompts than session 1: {diff}')
    stats1 = group_stats(lab, s1)
    stats2 = group_stats(lab, s2) if s2 else {}
    prim = primaries(lab)
    tol = float((lab.get('replication') or {}).get('tolerance', 0.10))
    rows = []
    hold = []
    null_rule = False
    for p in prim:
        c1 = compare(lab, stats1, s1['cells'], p)
        c2 = compare(lab, stats2, s2['cells'], p) if s2 else None
        rep = None
        if s2 and c1.get('status') == 'timeouts':
            # A pre-registered "did not finish in time" finding must also hold on the second day.
            rep = 'yes' if (c2 or {}).get('status') == 'timeouts' and c2.get('sides') == c1.get('sides') else \
                ('NO' if (c2 or {}).get('status') == 'complete' else 'n/a')
        elif s2:
            if c1.get('status') != 'complete' or (c2 or {}).get('status') != 'complete':
                rep = 'n/a'
            else:
                rep = 'yes' if repeated(c1, c2, tol) else 'NO'
        where = f"{p['model']} / {p['length']} / {p['metric']}: {p['a']} vs {p['b']}"
        if rep == 'yes' and c1.get('separated') == 'no' and (c1['ratio'] > 1) != (c2['ratio'] > 1):
            null_rule = True  # the earlier rule would have held it: say which rule was used
            notes.append(f'{where}: neither session separated a difference, and the earlier same-direction test would have '
                         f'failed it (ratio {c1["ratio"]:.3f}, then {c2["ratio"]:.3f}); the replication rule of 24 November 2026 does '
                         f'not compare the direction of a comparison neither session separated. A plan frozen before that date '
                         f'stated the stricter rule; the report must say so.')
        if c1.get('status') == 'timeouts':
            pass  # pre-registered: a side that never finishes in time is the finding
        elif c1.get('status') != 'complete':
            hold.append(f'primary comparison incomplete in session 1: {where}')
        if rep in ('n/a', 'NO') and c1.get('status') in ('complete', 'timeouts'):
            hold.append(f'primary comparison {"not measured completely" if rep == "n/a" else "did not repeat"} in session 2: {where}')
        rows.append({**{k: p[k] for k in ('measurement', 'model', 'length', 'metric', 'a', 'b')},
                     'session1': {k: v for k, v in c1.items()}, 'session2': c2, 'repeated': rep})
    if problems:
        hold = [f'verification: {x}' for x in problems] + hold
    # Generated data files: one row per value of every attempt (smoke and warm-ups included, marked).
    for sess, name in ((s1, f'{slug}-data.csv'), (s2, f'{slug}-data-s2.csv')):
        if not sess:
            continue
        import csv
        with open(os.path.join(rundir, name), 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['session', 'attempt', 'kind', 'round', *CELL_KEYS, 'outcome', 'reason', 'metric', 'value', 'unit', 'start', 'end', 'log'])
            for a in sess['attempts']:
                base = [sess['session'], a['seq'], a['kind'], a.get('round') or '', *a['cell'], a['outcome'], a['reason']]
                vals = a['values'] or {}
                if not vals:
                    w.writerow(base + ['', '', '', a['start'], a['end'], a['log']])
                for m, v in vals.items():
                    w.writerow(base + [m, repr(v), lab['metrics'][m]['unit'], a['start'], a['end'], a['log']])
    # Derived figures.
    L = ['# Derived figures (computed by labverify.py from the lab runner\'s ledger and logs; not written by hand)', '']
    pol = (f'Policy (from the frozen plan): {lab["warmups"]} discarded warm-up(s) per cell, then the planned measured runs in a '
           f'seeded interleaved order; a run that fails or breaks a check or the conditions rule is invalid and retried, at most '
           f'{lab["max_retries"]} times per cell; a run past {lab["timeout_s"]} s is recorded as a timeout and not retried. '
           f'A cell with every planned run valid is complete; otherwise it is incomplete and gets no comparison'
           + ('; a cell whose runs all time out is reported as "did not finish in time" (pre-registered)' if lab.get('timeout_is_result') else '') + '.')
    L += [pol, '']
    for sess in (s1, s2):
        if not sess:
            continue
        h, e = sess['header'], sess['end']
        n_att = len(sess['attempts'])
        by = {}
        for a in sess['attempts']:
            by[a['outcome']] = by.get(a['outcome'], 0) + 1
        loads = [a['conditions'].get('load1') for a in sess['attempts'] if isinstance(a['conditions'].get('load1'), (int, float))]
        therm = sum(1 for a in sess['attempts'] if a['conditions'].get('thermal_warning'))
        L += [f'## Session {sess["session"]}', '',
              f'Started {h.get("started", "?")}, ended {e.get("finished", "not finished")} ({e.get("reason", "-")}). '
              f'Pipeline commit {str(h.get("commit", "?"))[:12]}; runner {h.get("runner_sha256", "?")[:12]}. '
              f'{n_att} attempts: ' + ', '.join(f'{v} {k}' for k, v in sorted(by.items())) + '. '
              + (f'Load average before runs {min(loads):.2f} to {max(loads):.2f}; ' if loads else '')
              + f'thermal warning before {therm} run(s).', '']
        reasons = {}
        for a in sess['attempts']:
            if a['outcome'] != 'ok':
                reasons.setdefault(a['reason'][:120], []).append(str(a['seq']))
        if reasons:
            L += ['Attempts that did not count (attempt numbers):', ''] + [f'- {r}: {", ".join(v)}' for r, v in reasons.items()] + ['']
    L += ['## Groups (session 1)', '',
          '| Measurement | Model | Engine | Config | Length | Metric | n | Mean | SD | Min | Max | CV % | Status |',
          '|---|---|---|---|---|---|---|---|---|---|---|---|---|']
    for (k, m), (n, mean, sd, lo, hi, _) in sorted(stats1.items()):
        s = s1['cells'][k]
        cv = 100 * sd / mean if mean else 0.0
        status = s['status'] + (f', {s["timeout"]} timeout' if s['timeout'] else '') + (f', {s["not_run"]} not run' if s['not_run'] else '')
        L.append(f'| {" | ".join(k)} | {m} | {n} | {_fmt(mean)} {lab["metrics"][m]["unit"]} | {_fmt(sd)} | {_fmt(lo)} | {_fmt(hi)} | '
                 f'{cv:.1f}{" (unstable)" if cv > 10 else ""} | {status} |')
    for k, s in sorted(s1['cells'].items()):
        if not s['ok']:
            L.append(f'| {" | ".join(k)} | - | 0 | - | - | - | - | - | {s["status"]}, {s["timeout"]} timeout, {s["not_run"]} not run |')
    L += ['', '## Comparisons (session 1)', '',
          f'"A / B" is the ratio of means with its 95% confidence interval (Fieller\'s method: each side\'s mean and the '
          f'squared standard error of the mean, Student\'s t at the 97.5% point with Welch-Satterthwaite degrees of freedom). '
          f'"Separated" means that whole interval lies '
          f'above {SEP_MARGIN} or below {1 / SEP_MARGIN:.4f}; only separated differences may be reported as real, and a pair that '
          f'is not separated is "no difference we could separate", never "the same". Primary comparisons were pre-registered; '
          f'the others are exploratory and must be labelled so. Incomplete cells are not compared.', '',
          '| Primary | Measurement | Model | Length | Metric | A | B | Mean A | Mean B | A / B | 95% CI | Separated |',
          '|---|---|---|---|---|---|---|---|---|---|---|---|']
    pkeys = {(p['ka'], p['kb'], p['metric']) for p in prim}
    groups = {}
    for (k, m) in stats1:
        groups.setdefault((k[0], k[1], k[4], m), []).append(k)
    for (meas, model, length, m), ks in sorted(groups.items()):
        ks.sort(key=lambda k: (k[2], k[3]))
        for i in range(len(ks)):
            for j in range(i + 1, len(ks)):
                ka, kb = ks[i], ks[j]
                if (kb, ka, m) in pkeys:
                    ka, kb = kb, ka
                if s1['cells'][ka]['status'] != 'complete' or s1['cells'][kb]['status'] != 'complete':
                    continue
                va, vb = stats1[(ka, m)], stats1[(kb, m)]
                if not va[1] or not vb[1]:
                    continue
                ci = ratio_ci(va[5], vb[5])
                sep = 'no' if ci is None else 'yes' if (ci[0] > SEP_MARGIN or ci[1] < 1 / SEP_MARGIN) else 'no'
                L.append(f'| {"yes" if (ka, kb, m) in pkeys else ""} | {meas} | {model} | {length} | {m} | {ka[2]} {ka[3]} | {kb[2]} {kb[3]} | '
                         f'{_fmt(va[1])} | {_fmt(vb[1])} | {va[1] / vb[1]:.3f}x | {f"{ci[0]:.3f} to {ci[1]:.3f}" if ci else "n/a"} | {sep} |')
    if s2:
        L += ['', '## Second session (a later day)', '',
              (f'Each pre-registered primary comparison measured again in a fresh session. "Repeated" means the same Separated '
               f'verdict, the same direction, and a ratio within {tol:.0%} of session 1\'s. Same team, same machine: this shows '
               f'repeatability, not independent replication.' if not null_rule else
               f'Each pre-registered primary comparison measured again in a fresh session. "Repeated" means both sessions have a '
               f'bounded interval, the same Separated verdict, a ratio within {tol:.0%} of session 1\'s, and, for a comparison '
               f'that separated, the same direction (rule of 24 November 2026). A comparison neither session separated claims no '
               f'direction, so which side of 1 its ratio falls on is not compared; "repeated" then means only that neither '
               f'session separated a difference, not that the two are equivalent. Same team, same machine: this shows '
               f'repeatability, not independent replication.'), '',
              '| Model | Length | Metric | A vs B | Session 1 | Session 2 | Repeated |', '|---|---|---|---|---|---|---|']

        def ftxt(c):
            if not c or c.get('status') != 'complete':
                return (c or {}).get('status', '-')
            return f"{c['ratio']:.3f}x ({c['ci'][0]:.3f} to {c['ci'][1]:.3f}), {c['separated']}" if c.get('ci') else f"{c['ratio']:.3f}x, no interval"
        for r in rows:
            L.append(f"| {r['model']} | {r['length']} | {r['metric']} | {r['a']} vs {r['b']} | {ftxt(r['session1'])} | {ftxt(r['session2'])} | {r['repeated']} |")
        ok_n = sum(1 for r in rows if r['repeated'] == 'yes')
        L += ['', f'Repeated: {ok_n} of {len(rows)} primary comparisons.']
    # The generated results block: inserted into the report's ## Results verbatim and checked byte for byte.
    G = [START, '']
    for (meas, model, m) in sorted({(k[0], k[1], m) for (k, m) in stats1 if lab['metrics'][m].get('report', True)}):
        name = lab['metrics'][m].get('label') or m
        G += [f'**{model}{"" if meas == "main" else ", " + meas}: {name}**', '',
              '| Engine | Settings | Length | Runs | Mean | SD | Min to max |', '|---|---|---|---|---|---|---|']
        for k in sorted((k for (k, mm) in stats1 if (k[0], k[1], mm) == (meas, model, m)),
                        key=lambda k: (k[2], k[3], int(k[4]) if k[4].isdigit() else 0, k[4])):
            n, mean, sd, lo, hi, _ = stats1[(k, m)]
            inc = '' if s1['cells'][k]['status'] == 'complete' else f' ({s1["cells"][k]["status"]})'
            G.append(f'| {k[2]} | {k[3]} | {k[4]} | {n}{inc} | {_fmt(mean)} {lab["metrics"][m]["unit"]} | {_fmt(sd)} | {_fmt(lo)} to {_fmt(hi)} |')
        G.append('')
    G += ['**Pre-registered comparisons**', '']
    for r, p in zip(rows, prim):
        c1 = r['session1']
        if c1.get('status') != 'complete':
            G.append(f"- {p['model']}, {p['length']}, {lab['metrics'].get(p['metric'], {}).get('label') or p['metric']}: "
                     f"{p['a']} against {p['b']}: {c1.get('status')}{(' (' + c1['note'] + ')') if c1.get('note') else ''}.")
        else:
            G.append(_claim(lab, p, c1, r['session2'] if s2 else None))
    G += ['', END]
    L += ['', '## Results block (generated)', ''] + G
    if notes:
        L += ['', '## Notes', ''] + [f'- {x}' for x in dict.fromkeys(notes)]
    if problems:
        L += ['', '## Verification problems', ''] + [f'- {x}' for x in problems]
    if hold:
        L += ['', '## Holds', ''] + [f'- {x}' for x in hold]
    open(derived_out, 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    verdict = {'ok': not hold, 'hold': hold, 'sessions': 2 if s2 else 1, 'primaries': rows,
               'problems': problems, 'tested_on': str(s1['header'].get('started', ''))[:10]}
    json.dump(verdict, open(verdict_out, 'w'), indent=1, default=str)
    n1 = sum(1 for a in s1['attempts'] if a['kind'] == 'measure')
    print('\n'.join(hold[:25]) or f'ok: session 1 {n1} measured attempts verified' + (f', session 2 {sum(1 for a in s2["attempts"] if a["kind"] == "measure")}' if s2 else ''))
    return 1 if hold else 0


# ---------------------------------------------------------------------------------------------------- results block

def generated_block(derived):
    d = open(derived, encoding='utf-8').read()
    i, j = d.find(START), d.find(END)
    if i < 0 or j < 0:
        return None
    return d[i:j + len(END)]


def results_insert(article, derived):
    """Put the generated results block at the top of ## Results (replacing an earlier one or any tables there),
    keeping the write-up's sentences. Idempotent."""
    block = generated_block(derived)
    if not block:
        print('no generated results block in the statistics')
        return 1
    s = open(article, encoding='utf-8').read()
    sm = re.search(r'^## Results\n(.*?)(?=^## |\Z)', s, re.S | re.M)
    if not sm:
        print('no ## Results section')
        return 1
    sec = sm.group(1)
    i, j = sec.find(START), sec.find(END)
    if i >= 0 and j >= 0:
        sec = sec[:i] + sec[j + len(END):]
    prose = [b for b in re.split(r'\n\s*\n', sec) if b.strip() and not b.lstrip().startswith('|')]
    new = '## Results\n\n' + block + '\n\n' + '\n\n'.join(p.strip() for p in prose) + ('\n\n' if prose else '')
    s = s[:sm.start()] + new + s[sm.end():]
    open(article, 'w', encoding='utf-8').write(s)
    print('ok')
    return 0


def results_check(article, derived):
    """The report's generated block is byte for byte the one computed from the data, and ## Results has no other table."""
    block = generated_block(derived)
    s = open(article, encoding='utf-8').read()
    if not block:
        print('no generated results block in the statistics')
        return 1
    if s.count(START) != 1 or s.count(END) != 1:
        print('the report must contain the generated results block exactly once')
        return 1
    if block not in s:
        print('the generated results block in the report was edited (it differs from the one computed from the data)')
        return 1
    sm = re.search(r'^## Results\n(.*?)(?=^## |\Z)', s, re.S | re.M)
    if not sm or block not in sm.group(1):
        print('the generated results block is not in ## Results')
        return 1
    rest = sm.group(1).replace(block, '')
    if re.search(r'^\s*\|', rest, re.M):
        print('## Results has a table outside the generated block')
        return 1
    print('ok')
    return 0


def claims_text(derived):
    """The pre-registered comparison lines of the generated block (headline figures must come from here)."""
    b = generated_block(derived) or ''
    i = b.find('**Pre-registered comparisons**')
    return b[i:] if i >= 0 else ''


def main(cmd, *a):
    if cmd == 'check':
        plan = json.load(open(a[0]))
        art = open(a[1], encoding='utf-8').read() if len(a) > 1 else None
        probs = check_lab_plan(plan, art)
        print('\n'.join(probs) or 'ok')
        return 1 if probs else 0
    if cmd == 'verify':
        opts = dict(x.split('=', 1) for x in a[5:] if '=' in x)
        return lab_verify(a[0], a[1], a[2], a[3], a[4], slug=opts.get('--slug'), sessions=opts.get('--sessions', '1'))
    if cmd == 'results-insert':
        return results_insert(*a)
    if cmd == 'results-check':
        return results_check(*a)
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(*sys.argv[1:]))
