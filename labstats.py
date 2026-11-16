"""Small statistics for labverify.py, standard library only (no scipy).

ratio_ci(): Fieller's confidence interval for the ratio of two independent means with unequal variances
(the approach Kalibera and Jones recommend for "A is x% faster" claims), with Welch-Satterthwaite degrees of
freedom on the linearised ratio. Returns (low, high), or None when the interval is unbounded (the denominator's
mean is not clearly away from zero) or a group has fewer than two runs.
"""
import math


def _betacf(a, b, x):
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
        c = 1.0 + aa / c if abs(1.0 + aa / c) > 1e-300 else 1e-300
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
        c = 1.0 + aa / c if abs(1.0 + aa / c) > 1e-300 else 1e-300
        de = d * c
        h *= de
        if abs(de - 1.0) < 1e-12:
            break
    return h


def _ibeta(a, b, x):
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    lbt = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x)
    if x < (a + 1) / (a + b + 2):
        return math.exp(lbt) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbt) * _betacf(b, a, 1 - x) / b


def t_cdf(t, df):
    x = df / (df + t * t)
    p = 0.5 * _ibeta(df / 2.0, 0.5, x)
    return 1.0 - p if t > 0 else p


def t_quantile(p, df):
    lo, hi = 0.0, 1e6
    for _ in range(200):
        mid = (lo + hi) / 2
        if t_cdf(mid, df) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def ratio_ci(a_vals, b_vals, level=0.95):
    na, nb = len(a_vals), len(b_vals)
    if na < 2 or nb < 2:
        return None
    ma, mb = sum(a_vals) / na, sum(b_vals) / nb
    if mb == 0:
        return None
    va = sum((x - ma) ** 2 for x in a_vals) / (na - 1) / na
    vb = sum((x - mb) ** 2 for x in b_vals) / (nb - 1) / nb
    r = ma / mb
    num = (va + r * r * vb) ** 2
    den = (va * va / (na - 1) if va else 0.0) + (r ** 4 * vb * vb / (nb - 1) if vb else 0.0)
    df = num / den if den > 0 else float(na + nb - 2)
    t = t_quantile(1 - (1 - level) / 2, max(df, 1.0))
    qa = mb * mb - t * t * vb
    if qa <= 0:
        return None
    disc = t * t * (ma * ma * vb + mb * mb * va - t * t * va * vb)
    if disc < 0:
        return None
    s = math.sqrt(disc)
    return ((ma * mb - s) / qa, (ma * mb + s) / qa)
