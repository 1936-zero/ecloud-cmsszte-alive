#!/usr/bin/env python3
"""path_B SPICE HEART keepalive loop (claim=false).

Wraps path_b_keepalive_package.run_path_b_keepalive in a periodic loop
mirroring main.py keepalive (default interval=300s).

Hard pins:
  - production_claim=false
  - public_ecloud_9222 only (no jtydn)
  - never log -k / plain / connectStr
  - ticket_mode default zeros
  - FREEZE a46d55cd523da9fd
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_L3 = Path(__file__).resolve().parent
if str(_L3) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(_L3))

from path_b_keepalive_package import (  # noqa: E402
    DEFAULT_CAG_HOST,
    DEFAULT_PLAIN,
    DEFAULT_PRE,
    DEFAULT_POST,
    DEFAULT_TICKET_MODE,
    FREEZE_CITE,
    PRODUCTION_CLAIM,
    run_path_b_keepalive,
)

log = logging.getLogger("path_b_loop")

PRODUCTION_CLAIM = False  # re-pin
PIN_PRODUCT_LINE = "public_ecloud_9222"
BAN_LINES = ("jtydn", "爱家", "cmcc-jtydn:9223")


def _summary_row(round_i: int, result: Dict[str, Any], elapsed_s: float) -> Dict[str, Any]:
    """Secret-free per-round summary."""
    return {
        "round": round_i,
        "ts": datetime.now().isoformat(timespec="seconds"),
        "elapsed_s": round(elapsed_s, 3),
        "ok_heart_keepalive": bool(result.get("ok_heart_keepalive")),
        "ok_redq_s2c": bool(result.get("ok_redq_s2c")),
        "ok_tls": bool(result.get("ok_tls")),
        "ok_auth220": bool(result.get("ok_auth220")),
        "heart_count": int(result.get("heart_count") or 0),
        "agent_hb_count": int(result.get("agent_hb_count") or 0),
        "s2c_frame_count": int(result.get("s2c_frame_count") or 0),
        "s2c_type_hist": result.get("s2c_type_hist") or {},
        "error": result.get("error") or "",
        "host": result.get("host"),
        "ticket_mode": result.get("ticket_mode"),
        "session_nudge": result.get("session_nudge"),
        "heart_listen_s": result.get("heart_listen_s"),
        "production_claim": False,
        "dual_evidence_ok": bool(result.get("dual_evidence_ok", False)),
        "freeze_cite": FREEZE_CITE,
    }


def run_path_b_keepalive_loop(
    *,
    host: str = DEFAULT_CAG_HOST,
    plain: Path = Path(DEFAULT_PLAIN),
    pre: Path = Path(DEFAULT_PRE),
    post: Path = Path(DEFAULT_POST),
    heart_listen: float = 60.0,
    ticket_mode: str = DEFAULT_TICKET_MODE,
    session_nudge: Optional[bool] = None,
    agent_hb_every: float = 0.0,
    interval: int = 300,
    max_rounds: Optional[int] = None,
    out_dir: Optional[Path] = None,
    stop_on_fatal: bool = False,
) -> Dict[str, Any]:
    """Periodic path_B HEART sessions.

    Each round: full CAG connect + heart_listen, then sleep `interval` seconds.
    Does not replace HTTP login; SPICE plane only. claim=false forever here.
    """
    plain = Path(plain)
    if not plain.is_file():
        raise FileNotFoundError(f"plain missing (not logging path contents): exists=False")

    if out_dir is None:
        out_dir = _L3.parent / "reports" / "r26_live" / "path_b_soak"
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now().strftime("%Y%m%dT%H%M%S")
    summary_path = out_dir / f"path_b_soak_{run_id}.jsonl"
    meta_path = out_dir / f"path_b_soak_{run_id}_meta.json"

    meta = {
        "run_id": run_id,
        "started": datetime.now().isoformat(timespec="seconds"),
        "host": host,
        "heart_listen_s": float(heart_listen),
        "interval_s": int(interval),
        "max_rounds": max_rounds,
        "ticket_mode": ticket_mode,
        "session_nudge": session_nudge,
        "agent_hb_every": float(agent_hb_every),
        "plain_present": plain.is_file(),
        "plain_size": plain.stat().st_size if plain.is_file() else 0,
        "production_claim": False,
        "dual_evidence_ok": False,
        "agent_dual_ok": False,
        "freeze_cite": FREEZE_CITE,
        "pin_product_line": PIN_PRODUCT_LINE,
        "ban_lines": list(BAN_LINES),
        "summary_jsonl": str(summary_path),
        "note": "SPICE path_B HEART loop; does NOT dump -k/plain; claim=false",
    }
    meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    log.info(
        "path_B soak start run_id=%s interval=%ds heart_listen=%.1fs max_rounds=%s claim=false",
        run_id,
        interval,
        heart_listen,
        max_rounds if max_rounds is not None else "inf",
    )

    rounds = 0
    ok_heart_rounds = 0
    ok_redq_rounds = 0
    fail_rounds = 0
    rows: List[Dict[str, Any]] = []

    try:
        while max_rounds is None or rounds < max_rounds:
            rounds += 1
            t0 = time.time()
            round_out = out_dir / f"path_b_soak_{run_id}_r{rounds:04d}.json"
            err_msg = ""
            result: Dict[str, Any] = {}
            try:
                result = run_path_b_keepalive(
                    host=host,
                    plain=plain,
                    heart_listen=float(heart_listen),
                    ticket_mode=str(ticket_mode),
                    session_nudge=session_nudge,
                    agent_hb_every=float(agent_hb_every),
                    pre=pre,
                    post=post,
                    out=round_out,
                )
            except Exception as e:
                err_msg = f"{type(e).__name__}:{e}"
                result = {
                    "ok_heart_keepalive": False,
                    "ok_redq_s2c": False,
                    "error": err_msg,
                    "host": host,
                    "ticket_mode": ticket_mode,
                    "session_nudge": session_nudge,
                    "heart_listen_s": heart_listen,
                    "heart_count": 0,
                    "agent_hb_count": 0,
                    "s2c_frame_count": 0,
                    "s2c_type_hist": {},
                    "production_claim": False,
                }
                log.exception("[%d] path_B round exception", rounds)

            elapsed = time.time() - t0
            row = _summary_row(rounds, result, elapsed)
            if err_msg and not row.get("error"):
                row["error"] = err_msg
            rows.append(row)

            with summary_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")

            if row["ok_heart_keepalive"]:
                ok_heart_rounds += 1
                log.info(
                    "[%d] HEART ok heart_count=%s s2c=%s elapsed=%.1fs",
                    rounds,
                    row["heart_count"],
                    row["s2c_frame_count"],
                    elapsed,
                )
            elif row["ok_redq_s2c"]:
                ok_redq_rounds += 1
                log.warning(
                    "[%d] REDQ ok but HEART fail err=%s elapsed=%.1fs",
                    rounds,
                    (row.get("error") or "")[:80],
                    elapsed,
                )
            else:
                fail_rounds += 1
                log.error(
                    "[%d] FAIL err=%s elapsed=%.1fs",
                    rounds,
                    (row.get("error") or "unknown")[:80],
                    elapsed,
                )
                if stop_on_fatal:
                    break

            if max_rounds is not None and rounds >= max_rounds:
                break
            log.info("[%d] sleep %ds before next round", rounds, interval)
            time.sleep(int(interval))
    finally:
        finished = {
            "run_id": run_id,
            "finished": datetime.now().isoformat(timespec="seconds"),
            "rounds": rounds,
            "ok_heart_rounds": ok_heart_rounds,
            "ok_redq_rounds": ok_redq_rounds,
            "fail_rounds": fail_rounds,
            "production_claim": False,
            "freeze_cite": FREEZE_CITE,
            "summary_jsonl": str(summary_path),
            "meta": str(meta_path),
        }
        fin_path = out_dir / f"path_b_soak_{run_id}_final.json"
        text = json.dumps(finished, indent=2, ensure_ascii=False)
        fin_path.write_text(text, encoding="utf-8")
        finished["final_sha16"] = hashlib.sha256(text.encode()).hexdigest()[:16]
        log.info(
            "path_B soak end run_id=%s rounds=%d ok_heart=%d redq_only=%d fail=%d claim=false",
            run_id,
            rounds,
            ok_heart_rounds,
            ok_redq_rounds,
            fail_rounds,
        )
        finished["rows_tail"] = rows[-3:]
        return finished
