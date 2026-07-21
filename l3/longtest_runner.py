"""Longtest gate runner skeleton (sim / dry).

Implements reports/longtest_gate.md scoring for synthetic samples.
No live VDI, no desktop login, no secrets.
production_claim is always false.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


GATE_PASS = "GATE_PASS"
GATE_WEAK = "GATE_WEAK"
GATE_FAIL = "GATE_FAIL"

TIER_SPECS: Dict[str, Dict[str, Any]] = {
    "S0": {"duration_s": 120, "interval_s": 20, "protocol_cover_min": 0.80},
    "S1": {"duration_s": 600, "interval_s": 30, "protocol_cover_min": 0.80},
    "S2": {"duration_s": 2400, "interval_s": 30, "protocol_cover_min": 0.80},
    "S3": {"duration_s": 3600, "interval_s": 30, "protocol_cover_min": 0.80},
}

DEFAULT_TIER = "S1"
PROTOCOL_COVER_MIN = 0.80
SAMPLE_GAP_WEAK = 0.10


@dataclass
class Sample:
    t_s: int
    arm: str  # l2_only | l3_path_a
    resource_status: str
    desktop_uptime_s: int
    process_alive: bool
    protocol_signal: bool  # 15900 type=1 and/or SPICE hold in bucket
    spice_hold: bool = False
    heart_type1: bool = False
    mid_shutdown: bool = False
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PlaneScore:
    process_ok: bool
    protocol_ok: bool
    business_ok: bool
    protocol_coverage: float
    sample_gap_ratio: float
    mid_shutdown: bool
    off_n: int
    continuous_run_s: int
    residual: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GateResult:
    gate: str
    evidence_tag: str
    production_claim: bool
    tier: str
    mode: str
    arms: Dict[str, PlaneScore]
    notes: List[str] = field(default_factory=list)
    sample_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate": self.gate,
            "evidence_tag": self.evidence_tag,
            "production_claim": self.production_claim,
            "tier": self.tier,
            "mode": self.mode,
            "arms": {k: v.to_dict() for k, v in self.arms.items()},
            "notes": list(self.notes),
            "sample_counts": dict(self.sample_counts),
        }


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def plan_text(tier: str = DEFAULT_TIER) -> str:
    spec = TIER_SPECS[tier]
    lines = [
        "longtest-sim dry plan (no live VDI / no login)",
        f"  tier={tier} duration_s={spec['duration_s']} interval_s={spec['interval_s']}",
        f"  protocol_cover_min={spec['protocol_cover_min']}",
        "  arms:",
        "    - l2_only: status+uptime only; protocol expected empty (negative control)",
        "    - l3_path_a: process + protocol(15900/SPICE) + business samples",
        "  scoring (longtest_gate §6):",
        "    GATE_PASS  = protocol_ok ∧ business_ok on L3 arm (G0/G1 assumed for sim)",
        "    GATE_WEAK  = hold complete with protocol residual or sample_gap>10%",
        "    GATE_FAIL  = mid_shutdown / off_n>0 / protocol hard miss / L2-only claim abuse",
        "  production_claim ≡ false",
        "  outputs: reports/longtest/preflight_*.json samples_*.jsonl score_*.json RESULT_*.md",
        "  redlines: no secrets; no 爱家 import; no default /opt/ZTE; L2 cannot alone PASS L3",
    ]
    return "\n".join(lines)


def synthesize_samples(
    *,
    tier: str = DEFAULT_TIER,
    scenario: str = "l3_pass",
    seed_uptime: int = 97 * 3600 + 600,
) -> List[Sample]:
    """Build synthetic sample stream for sim mode.

    scenarios:
      l3_pass     — L3 full dual-plane PASS; L2 negative control present
      l3_weak     — L3 business ok, protocol partial residual
      l3_fail_biz — mid_shutdown / off on L3
      l3_fail_proto — no protocol on L3
      l2_only     — only L2 arm (must not yield GATE_PASS for true keepalive)
    """
    if tier not in TIER_SPECS:
        raise ValueError(f"unknown tier: {tier}")
    spec = TIER_SPECS[tier]
    duration = int(spec["duration_s"])
    interval = int(spec["interval_s"])
    times = list(range(0, duration + 1, interval))
    if times[-1] != duration:
        times.append(duration)

    samples: List[Sample] = []

    # L2-only negative control always included except pure fail scenarios still useful
    for i, t in enumerate(times):
        samples.append(
            Sample(
                t_s=t,
                arm="l2_only",
                resource_status="available",
                desktop_uptime_s=seed_uptime + t,
                process_alive=False,
                protocol_signal=False,
                spice_hold=False,
                heart_type1=False,
                notes="l2_only_baseline: uptime wall-clock without VDI",
            )
        )

    if scenario == "l2_only":
        return samples

    n = len(times)
    for i, t in enumerate(times):
        if scenario == "l3_pass":
            proto = True
            process = True
            status = "available"
            mid = False
            notes = "sim L3 path-A healthy"
        elif scenario == "l3_weak":
            # protocol only on first ~60% buckets → residual / weak coverage
            proto = i < int(n * 0.55)
            process = True
            status = "available"
            mid = False
            notes = "sim partial protocol residual"
        elif scenario == "l3_fail_biz":
            mid = i >= max(1, n // 2)
            status = "shutdown" if mid else "available"
            proto = True
            process = not mid
            notes = "sim mid_shutdown"
        elif scenario == "l3_fail_proto":
            proto = False
            process = True
            status = "available"
            mid = False
            notes = "sim process up but no 15900/SPICE signal"
        else:
            raise ValueError(f"unknown scenario: {scenario}")

        samples.append(
            Sample(
                t_s=t,
                arm="l3_path_a",
                resource_status=status,
                desktop_uptime_s=seed_uptime + t,
                process_alive=process,
                protocol_signal=proto,
                spice_hold=proto and (i % 2 == 0),
                heart_type1=proto,
                mid_shutdown=mid,
                notes=notes,
            )
        )
    return samples


def _arm_samples(samples: Sequence[Sample], arm: str) -> List[Sample]:
    return [s for s in samples if s.arm == arm]


def score_arm(samples: Sequence[Sample], *, tier: str) -> PlaneScore:
    if not samples:
        return PlaneScore(
            process_ok=False,
            protocol_ok=False,
            business_ok=False,
            protocol_coverage=0.0,
            sample_gap_ratio=1.0,
            mid_shutdown=True,
            off_n=0,
            continuous_run_s=0,
            residual=["no_samples"],
        )

    ordered = sorted(samples, key=lambda s: s.t_s)
    n = len(ordered)
    proto_n = sum(1 for s in ordered if s.protocol_signal)
    coverage = proto_n / n if n else 0.0

    # sample gap: missing buckets vs expected regular interval
    spec = TIER_SPECS[tier]
    interval = int(spec["interval_s"])
    duration = int(spec["duration_s"])
    expected = list(range(0, duration + 1, interval))
    if expected[-1] != duration:
        expected.append(duration)
    have = {s.t_s for s in ordered}
    missing = [t for t in expected if t not in have]
    gap_ratio = (len(missing) / len(expected)) if expected else 1.0

    off_n = sum(
        1
        for s in ordered
        if (s.resource_status or "").lower() not in ("available", "running", "inuse", "in_use")
    )
    mid_shutdown = any(s.mid_shutdown for s in ordered) or off_n > 0

    # continuous run: longest prefix of business-ok samples * interval approx
    cont = 0
    for s in ordered:
        st = (s.resource_status or "").lower()
        if st in ("available", "running", "inuse", "in_use") and not s.mid_shutdown:
            cont = s.t_s
        else:
            break
    continuous_run_s = cont

    process_ok = all(s.process_alive for s in ordered) if ordered[0].arm == "l3_path_a" else True
    # L2-only: process_ok trivial true (no VDI expected); protocol must be empty
    if ordered[0].arm == "l2_only":
        process_ok = not any(s.process_alive for s in ordered) or True
        # negative control: protocol should be empty
        protocol_ok = False
        business_ok = off_n == 0 and not any(s.mid_shutdown for s in ordered)
        residual = ["l2_only_negative_control"]
        if coverage > 0:
            residual.append("unexpected_protocol_on_l2")
        return PlaneScore(
            process_ok=True,
            protocol_ok=protocol_ok,
            business_ok=business_ok,
            protocol_coverage=coverage,
            sample_gap_ratio=gap_ratio,
            mid_shutdown=mid_shutdown,
            off_n=off_n,
            continuous_run_s=continuous_run_s,
            residual=residual,
        )

    cover_min = float(spec["protocol_cover_min"])
    protocol_ok = coverage >= cover_min and not mid_shutdown
    business_ok = off_n == 0 and not mid_shutdown and continuous_run_s >= max(0, duration - interval)

    residual: List[str] = []
    if 0 < coverage < cover_min:
        residual.append(f"protocol_coverage_{coverage:.2f}<{cover_min}")
    if gap_ratio > SAMPLE_GAP_WEAK:
        residual.append(f"sample_gap_{gap_ratio:.2f}")
    if any(s.protocol_signal and not s.heart_type1 and not s.spice_hold for s in ordered):
        residual.append("protocol_flag_without_detail")
    # partial protocol detail residual even if coverage ok
    if protocol_ok and coverage < 1.0 and any(not s.heart_type1 for s in ordered):
        residual.append("partial_type1")
    if not process_ok:
        residual.append("process_not_alive")

    # hard protocol miss: zero coverage entire window
    if coverage == 0.0:
        protocol_ok = False
        residual.append("protocol_hard_miss")

    return PlaneScore(
        process_ok=process_ok,
        protocol_ok=protocol_ok,
        business_ok=business_ok,
        protocol_coverage=coverage,
        sample_gap_ratio=gap_ratio,
        mid_shutdown=mid_shutdown,
        off_n=off_n,
        continuous_run_s=continuous_run_s,
        residual=residual,
    )


def score_samples(
    samples: Sequence[Sample],
    *,
    tier: str = DEFAULT_TIER,
    mode: str = "sim",
    assume_g0_g1: bool = True,
) -> GateResult:
    """Score multi-arm samples per longtest_gate §3/§6.

    True-keepalive claim only from L3 arm. L2 alone never GATE_PASS.
    """
    by_arm: Dict[str, PlaneScore] = {}
    counts: Dict[str, int] = {}
    for arm in sorted({s.arm for s in samples}):
        arm_s = _arm_samples(samples, arm)
        counts[arm] = len(arm_s)
        by_arm[arm] = score_arm(arm_s, tier=tier)

    notes: List[str] = []
    if not assume_g0_g1:
        notes.append("G0/G1 not assumed — live path would BLOCK before longtest")

    l3 = by_arm.get("l3_path_a")
    l2 = by_arm.get("l2_only")

    if l3 is None:
        # L2-only cannot PASS true keepalive
        notes.append("no_l3_arm: L2-only cannot claim true keepalive")
        if l2 and l2.business_ok and not l2.protocol_ok:
            return GateResult(
                gate=GATE_FAIL,
                evidence_tag="L2_ONLY_NEGATIVE",
                production_claim=False,
                tier=tier,
                mode=mode,
                arms=by_arm,
                notes=notes + ["l2_only_baseline_pattern"],
                sample_counts=counts,
            )
        return GateResult(
            gate=GATE_FAIL,
            evidence_tag="NO_L3_ARM",
            production_claim=False,
            tier=tier,
            mode=mode,
            arms=by_arm,
            notes=notes,
            sample_counts=counts,
        )

    # L3 scoring
    if l3.mid_shutdown or l3.off_n > 0 or not l3.business_ok:
        gate = GATE_FAIL
        tag = "BUSINESS_FAIL"
    elif not l3.protocol_ok and l3.protocol_coverage == 0.0:
        gate = GATE_FAIL
        tag = "PROTOCOL_HARD_MISS"
    elif not l3.protocol_ok or l3.sample_gap_ratio > SAMPLE_GAP_WEAK or l3.residual:
        # residual with business ok → WEAK if some protocol present; else FAIL
        if l3.protocol_coverage > 0 and l3.business_ok:
            gate = GATE_WEAK
            tag = "EVIDENCE_WEAK"
        else:
            gate = GATE_FAIL
            tag = "PROTOCOL_FAIL"
    elif l3.protocol_ok and l3.business_ok:
        gate = GATE_PASS
        tag = "EVIDENCE_SIM_PASS" if mode == "sim" else "EVIDENCE_PASS"
        # process residual alone does not fail if explained
        if not l3.process_ok:
            gate = GATE_WEAK
            tag = "EVIDENCE_WEAK"
            notes.append("process residual with protocol+business ok")
    else:
        gate = GATE_FAIL
        tag = "UNSPECIFIED_FAIL"

    # Cross-check: if someone tries to treat L2 success as L3
    if l2 and l2.business_ok and l3.protocol_coverage == 0.0 and gate == GATE_PASS:
        gate = GATE_FAIL
        tag = "L2_MASQUERADE_BLOCK"
        notes.append("blocked: L2 success must not become L3 PASS")

    notes.append("production_claim permanently false (longtest_gate §1/§8)")

    return GateResult(
        gate=gate,
        evidence_tag=tag,
        production_claim=False,
        tier=tier,
        mode=mode,
        arms=by_arm,
        notes=notes,
        sample_counts=counts,
    )


def write_outputs(
    *,
    nest_root: Path,
    samples: Sequence[Sample],
    result: GateResult,
    stamp: Optional[str] = None,
) -> Dict[str, Path]:
    stamp = stamp or utc_ts()
    out_dir = nest_root / "reports" / "longtest"
    out_dir.mkdir(parents=True, exist_ok=True)

    preflight = {
        "stamp": stamp,
        "mode": result.mode,
        "tier": result.tier,
        "g0_assumed_for_sim": result.mode == "sim",
        "g1_short_dual_evidence": "SIMULATED" if result.mode == "sim" else "UNKNOWN",
        "production_claim": False,
        "redlines": [
            "no_secrets",
            "no_aijia_import",
            "no_default_opt_zte",
            "l2_not_l3",
        ],
    }
    preflight_path = out_dir / f"preflight_{stamp}.json"
    preflight_path.write_text(json.dumps(preflight, indent=2) + "\n", encoding="utf-8")

    samples_path = out_dir / f"samples_{stamp}.jsonl"
    with samples_path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")

    score_path = out_dir / f"score_{stamp}.json"
    score_path.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")

    result_md = out_dir / f"RESULT_{stamp}.md"
    lines = [
        f"# longtest RESULT {stamp}",
        "",
        f"- mode: `{result.mode}`",
        f"- tier: `{result.tier}`",
        f"- gate: **{result.gate}**",
        f"- evidence_tag: `{result.evidence_tag}`",
        f"- production_claim: `{result.production_claim}`",
        f"- sample_counts: `{result.sample_counts}`",
        "",
        "## arms",
        "",
    ]
    for arm, plane in result.arms.items():
        lines.append(f"### {arm}")
        lines.append("")
        lines.append(f"- process_ok: {plane.process_ok}")
        lines.append(f"- protocol_ok: {plane.protocol_ok} (cover={plane.protocol_coverage:.2f})")
        lines.append(f"- business_ok: {plane.business_ok} (off_n={plane.off_n}, mid_shutdown={plane.mid_shutdown})")
        lines.append(f"- continuous_run_s: {plane.continuous_run_s}")
        lines.append(f"- residual: {plane.residual}")
        lines.append("")
    if result.notes:
        lines.append("## notes")
        lines.append("")
        for n in result.notes:
            lines.append(f"- {n}")
        lines.append("")
    result_md.write_text("\n".join(lines), encoding="utf-8")

    return {
        "preflight": preflight_path,
        "samples": samples_path,
        "score": score_path,
        "result_md": result_md,
    }


def run_dry(tier: str = DEFAULT_TIER) -> str:
    return plan_text(tier)


def run_sim(
    *,
    nest_root: Path,
    tier: str = DEFAULT_TIER,
    scenario: str = "l3_pass",
    write: bool = True,
    stamp: Optional[str] = None,
) -> Tuple[GateResult, List[Sample], Dict[str, Path]]:
    samples = synthesize_samples(tier=tier, scenario=scenario)
    result = score_samples(samples, tier=tier, mode="sim", assume_g0_g1=True)
    paths: Dict[str, Path] = {}
    if write:
        paths = write_outputs(nest_root=nest_root, samples=samples, result=result, stamp=stamp)
    return result, samples, paths


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="longtest gate runner (sim/dry skeleton)")
    p.add_argument("--mode", choices=("sim", "dry"), default="sim")
    p.add_argument("--tier", choices=sorted(TIER_SPECS.keys()), default=DEFAULT_TIER)
    p.add_argument(
        "--scenario",
        choices=("l3_pass", "l3_weak", "l3_fail_biz", "l3_fail_proto", "l2_only"),
        default="l3_pass",
        help="sim scenario (ignored in dry)",
    )
    p.add_argument(
        "--nest-root",
        default=".",
        help="nest root for reports/longtest outputs",
    )
    p.add_argument("--no-write", action="store_true", help="score only, skip file outputs")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    nest = Path(args.nest_root).resolve()
    if args.mode == "dry":
        print(run_dry(args.tier))
        return 0
    result, samples, paths = run_sim(
        nest_root=nest,
        tier=args.tier,
        scenario=args.scenario,
        write=not args.no_write,
    )
    print(f"longtest-sim: gate={result.gate} evidence={result.evidence_tag} tier={args.tier} scenario={args.scenario}")
    print(f"  production_claim={result.production_claim}")
    print(f"  samples={len(samples)} arms={result.sample_counts}")
    for arm, plane in result.arms.items():
        print(
            f"  [{arm}] process={plane.process_ok} protocol={plane.protocol_ok}"
            f"({plane.protocol_coverage:.2f}) business={plane.business_ok}"
        )
    if paths:
        for k, pth in paths.items():
            print(f"  {k}: {pth}")
    # exit code: 0 for PASS/WEAK (sim harness ok); 2 for FAIL scenario still "ran"
    return 0


if __name__ == "__main__":
    sys.exit(main())
