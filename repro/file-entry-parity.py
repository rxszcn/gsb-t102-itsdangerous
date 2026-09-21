"""边界面板：同一份 token 从文件/流入口与从字符串入口各会得到什么结论。

十格：salt 命名参数、max_age、return_timestamp、load_unsafe 是否真永不抛、
位置参数顺序与字符串入口是否一致，外加非时间戳那两个类、salt 上下文隔离、
字符串入口现有行为三处回归。

用法（仓库根目录）：timeout 200 env PYTHONPATH=src .venv/bin/python repro/file-entry-parity.py
"""

from __future__ import annotations

import io
import sys
from datetime import datetime, timedelta, timezone

from freezegun import freeze_time

from itsdangerous.exc import BadData, BadSignature, SignatureExpired
from itsdangerous.serializer import Serializer
from itsdangerous.signer import Signer
from itsdangerous.timed import TimedSerializer
from itsdangerous.url_safe import URLSafeSerializer, URLSafeTimedSerializer

TS = datetime(2011, 6, 24, 0, 9, 5, tzinfo=timezone.utc)
LATER = TS + timedelta(days=2)
VALUE = {"id": 42}
results: list[tuple[str, bool, str]] = []


def cell(name):
    def deco(fn):
        try:
            msg = fn()
            results.append((name, True, msg or ""))
        except BaseException as e:  # noqa: BLE001
            results.append((name, False, f"{type(e).__name__}: {str(e)[:80]}"))
        return fn

    return deco


def timed_file(cls, salt="ctx"):
    """A TimedSerializer-ish instance plus a StringIO of a fresh token."""
    s = cls("secret-key", salt=salt)
    with freeze_time(TS):
        tok = s.dumps(VALUE)
    return s, io.StringIO(tok)


# ------------------------------------------------------- S1/S2 the raw crash
@cell("S1 TimedSerializer.load(f, salt=...) loads the salted token")
def s1():
    s, f = timed_file(TimedSerializer)
    assert s.load(f, salt="ctx") == VALUE
    return "value"


@cell("S2 URLSafeTimedSerializer.load(f, salt=...) loads the salted token")
def s2():
    s, f = timed_file(URLSafeTimedSerializer)
    assert s.load(f, salt="ctx") == VALUE
    return "value"


# -------------------------------------- S3..S6 expiry/timestamp via file API
@cell("S3 TimedSerializer.load(f, max_age=N) enforces expiry")
def s3():
    s, f = timed_file(TimedSerializer)
    with freeze_time(LATER):
        try:
            s.load(f, max_age=60)
        except SignatureExpired:
            return "SignatureExpired"
        raise AssertionError("expired token accepted through the file API")


@cell("S4 TimedSerializer.load(f, return_timestamp=True) returns (value, dt)")
def s4():
    s, f = timed_file(TimedSerializer)
    out = s.load(f, return_timestamp=True)
    assert out == (VALUE, TS), out
    assert isinstance(out[1], datetime) and out[1].tzinfo is timezone.utc
    return "tuple"


@cell("S5 TimedSerializer.load_unsafe(f, max_age=N) never fails")
def s5():
    s, f = timed_file(TimedSerializer)
    with freeze_time(LATER):
        out = s.load_unsafe(f, max_age=60)
    assert out == (False, VALUE), out
    return "(False, value)"


@cell("S6 URLSafeTimedSerializer.load_unsafe(f, max_age=N) never fails")
def s6():
    s, f = timed_file(URLSafeTimedSerializer)
    with freeze_time(LATER):
        out = s.load_unsafe(f, max_age=60)
    assert out == (False, VALUE), out
    return "(False, value)"


# ------------------------------------- S7 positional shape mirrors loads (guard)
@cell("S7 TimedSerializer.load(f, N) positional == loads(s, N)")
def s7():
    s, f = timed_file(TimedSerializer)
    with freeze_time(LATER):
        try:
            s.load(f, 60)
        except SignatureExpired:
            pass
        else:
            raise AssertionError("positional max_age regressed")
        # same token, same age, string API must agree
        with freeze_time(LATER):
            tok2 = s.dumps(VALUE)
        try:
            s.loads(tok2, 60)
        except SignatureExpired:
            pass
    return "consistent"


# ------------------------------------------------- S8 non-timed regression
@cell("S8 plain Serializer/URLSafeSerializer file API unchanged")
def s8():
    for cls in (Serializer, URLSafeSerializer):
        s = cls("secret-key", salt="ctx")
        tok = s.dumps(VALUE)
        assert s.load(io.StringIO(tok), "ctx") == VALUE, f"{cls.__name__} positional"
        assert s.load(io.StringIO(tok), salt="ctx") == VALUE, f"{cls.__name__} kw"
        assert s.load_unsafe(io.StringIO(tok), salt="ctx") == (True, VALUE)
        assert s.load(io.StringIO(tok)) == s.loads(tok)  # default salt
        for kw in ("max_age", "return_timestamp"):
            try:
                s.load(io.StringIO(tok), **{kw: 60})
            except TypeError:
                pass
            else:
                raise AssertionError(f"{cls.__name__} grew a {kw} parameter")
    return "unchanged"


# ------------------------------------------- S9 salt context isolation, no kwargs
@cell("S9 salt context isolation via the file API")
def s9():
    s, tok_f = timed_file(TimedSerializer, salt="ctx")
    other = TimedSerializer("secret-key")  # default salt
    try:
        other.load(tok_f)
    except BadSignature:
        pass
    else:
        raise AssertionError("cross-context token accepted")
    return "isolated"


@cell("S10 string API (loads/loads_unsafe) behaviour preserved")
def s10():
    s = TimedSerializer("secret-key", salt="ctx")
    with freeze_time(TS):
        tok = s.dumps(VALUE)
        assert s.loads(tok, salt="ctx") == VALUE
        assert s.loads(tok, max_age=60, salt="ctx") == VALUE
        assert s.loads(tok, return_timestamp=True, salt="ctx") == (VALUE, TS)
    with freeze_time(LATER):
        try:
            s.loads(tok, 60, salt="ctx")
        except SignatureExpired:
            pass
        else:
            raise AssertionError("loads positional max_age regressed")
        assert s.loads_unsafe(tok, 60, salt="ctx") == (False, VALUE)
        assert s.loads_unsafe(tok, salt="ctx") == (True, VALUE)
    Signer("k").sign("v")
    return "ok"


def main() -> int:
    bad = 0
    for name, ok, msg in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  <-- {msg}" if msg else ""))
        bad += 0 if ok else 1
    print(f"{len(results) - bad}/{len(results)} cells pass")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
