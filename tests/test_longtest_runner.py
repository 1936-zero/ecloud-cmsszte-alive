"""Unit tests for l3.longtest_runner (sim/dry skeleton)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from l3.longtest_runner import (
    GATE_FAIL,
    GATE_PASS,
    GATE_WEAK,
    Sample,
    main as runner_main,
    plan_text,
    run_dry,
    run_sim,
    score_samples,
    synthesize_samples,
    write_outputs,
)


class TestLongtestRunner(unittest.TestCase):
    def test_dry_plan_mentions_redlines(self):
        text = run_dry("S1")
        self.assertIn("production_claim", text)
        self.assertIn("l2_only", text)
        self.assertIn("no live vdi", text.lower())
        self.assertIn("tier=S0", plan_text("S0"))

    def test_sim_l3_pass(self):
        r, samples, _ = run_sim(
            nest_root=Path("."),
            tier="S0",
            scenario="l3_pass",
            write=False,
        )
        self.assertEqual(r.gate, GATE_PASS)
        self.assertTrue(r.evidence_tag.startswith("EVIDENCE_"))
        self.assertFalse(r.production_claim)
        self.assertIn("l3_path_a", r.arms)
        self.assertIn("l2_only", r.arms)
        self.assertTrue(r.arms["l3_path_a"].protocol_ok)
        self.assertTrue(r.arms["l3_path_a"].business_ok)
        self.assertFalse(r.arms["l2_only"].protocol_ok)
        self.assertGreater(len(samples), 0)

    def test_sim_l3_weak(self):
        r, _, _ = run_sim(
            nest_root=Path("."),
            tier="S0",
            scenario="l3_weak",
            write=False,
        )
        self.assertEqual(r.gate, GATE_WEAK)
        self.assertFalse(r.production_claim)

    def test_sim_l3_fail_business(self):
        r, _, _ = run_sim(
            nest_root=Path("."),
            tier="S0",
            scenario="l3_fail_biz",
            write=False,
        )
        self.assertEqual(r.gate, GATE_FAIL)
        self.assertIn("BUSINESS", r.evidence_tag)

    def test_sim_l3_fail_protocol(self):
        r, _, _ = run_sim(
            nest_root=Path("."),
            tier="S0",
            scenario="l3_fail_proto",
            write=False,
        )
        self.assertEqual(r.gate, GATE_FAIL)
        self.assertIn("PROTOCOL", r.evidence_tag)

    def test_l2_only_never_pass(self):
        r, _, _ = run_sim(
            nest_root=Path("."),
            tier="S0",
            scenario="l2_only",
            write=False,
        )
        self.assertEqual(r.gate, GATE_FAIL)
        self.assertNotEqual(r.evidence_tag, "EVIDENCE_SIM_PASS")
        self.assertFalse(r.production_claim)

    def test_write_outputs_no_secrets(self):
        samples = synthesize_samples(tier="S0", scenario="l3_pass")
        result = score_samples(samples, tier="S0", mode="sim")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paths = write_outputs(
                nest_root=root,
                samples=samples,
                result=result,
                stamp="TESTSTAMP",
            )
            for p in paths.values():
                self.assertTrue(p.is_file())
                text = p.read_text(encoding="utf-8")
                low = text.lower()
                for banned in ("password", "access_token", "-----begin", "ticket="):
                    self.assertNotIn(banned, low)
            score = json.loads(paths["score"].read_text(encoding="utf-8"))
            self.assertIs(score["production_claim"], False)
            self.assertEqual(score["gate"], result.gate)

    def test_score_empty_is_fail(self):
        r = score_samples([], tier="S0", mode="sim")
        self.assertEqual(r.gate, GATE_FAIL)

    def test_cli_dry_exit0(self):
        rc = runner_main(["--mode", "dry", "--tier", "S0"])
        self.assertEqual(rc, 0)

    def test_cli_sim_nowrite(self):
        rc = runner_main(
            [
                "--mode",
                "sim",
                "--tier",
                "S0",
                "--scenario",
                "l3_pass",
                "--no-write",
            ]
        )
        self.assertEqual(rc, 0)

    def test_sample_fields_stable(self):
        s = Sample(
            t_s=0,
            arm="l3_path_a",
            resource_status="available",
            desktop_uptime_s=1,
            process_alive=True,
            protocol_signal=True,
        )
        d = s.to_dict()
        self.assertEqual(d["arm"], "l3_path_a")
        self.assertIn("protocol_signal", d)


if __name__ == "__main__":
    unittest.main()
