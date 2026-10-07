#!/usr/bin/env python3
"""Build the regression evidence matrix for the four design gates.

Inputs (all read-only except the run directory this script reads):

  tests/test_cases.json        the frozen 159 design test cases -- NEVER written
  mock/scripts/case_map.csv    the curated case -> test mapping
  mock/evidence/runs/<ts>/*.log raw cargo output from that run

Outputs:

  mock/evidence/coverage_matrix.csv   one row per design case
  mock/evidence/summary.json           per-gate rollup
  mock/docs/REGRESSION.md              the human report

Why the mapping is a file and not derived
-----------------------------------------
A design case says what an operator must observe ("resources clearly
grouped"). A Rust test says what the code guarantees. Nothing in the repository
relates one to the other, and inferring it from a requirement id would produce a
matrix that looks complete while asserting nothing. So `case_map.csv` is a
deliberate, reviewable judgement, and this script only executes it.

Status vocabulary (deliberately narrow -- see `docs/REGRESSION.md`):

  PASS       every mapped test ran and passed
  FAIL       at least one mapped test ran and failed
  PARTIAL    some mapped tests ran, at least one was not found
  UNMAPPED   the case exists in the design but nothing verifies it here
  MANUAL     the case needs a human in a real environment; the mapped tests
             cover the machine-checkable contract only
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CASES_JSON = REPO / "tests" / "test_cases.json"
CASE_MAP = REPO / "mock" / "scripts" / "case_map.csv"
EVIDENCE_DIR = REPO / "mock" / "evidence"
REPORT = REPO / "mock" / "docs" / "REGRESSION.md"

LAYERS = ("UT", "IT", "ST", "UAT")

# cargo prints "<name>: test" when listing, and "<name> ... ok/FAILED" when running.
LISTED = re.compile(r"^(?P<name>.+?): test$")
RESULT = re.compile(r"^test (?P<name>.+?) \.\.\. (?P<verdict>.+)$")
SUMMARY = re.compile(r"^test result: (?P<ok>\w+)\. (?P<passed>\d+) passed; (?P<failed>\d+) failed;")

# A design case is "fully automated" when every one of its steps is checkable
# without a human; the design workbook already records this, and we refuse to
# contradict it upward -- a case the design calls manual stays manual.
MANUAL_LAYERS = {"UAT"}

# `summary.json` and `docs/REGRESSION.md` are two renderings of one dict. When
# they disagree on a key name, the matrix is still written and the report dies
# with a bare KeyError halfway down an f-string -- so the failure surfaces as a
# traceback with no indication that the CSV beside it is fine. Checking the
# contract up front turns that into one named line.
REQUIRED_SUMMARY_KEYS = (
    "run", "total_cases", "total_tests_executed", "tests_passed", "tests_failed",
    "tests_ignored", "ignored_tests", "gate_exit", "by_layer", "failing_cases",
    "unmapped_cases",
)


@dataclass
class Case:
    case_id: str
    layer: str
    requirement: str
    design_ref: str
    title: str
    objective: str
    expected: str
    design_automation: str
    priority: str
    mapped: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class RunResult:
    passed: set[str] = field(default_factory=set)
    failed: set[str] = field(default_factory=dict)  # name -> reason
    ignored: set[str] = field(default_factory=set)
    ran: set[str] = field(default_factory=set)
    gate_exit: dict[str, int] = field(default_factory=dict)


def load_cases() -> list[Case]:
    data = json.loads(CASES_JSON.read_text(encoding="utf-8"))
    columns = data["columns"]
    idx = {name: i for i, name in enumerate(columns)}
    cases: list[Case] = []
    for layer in LAYERS:
        for row in data[layer]:
            cases.append(
                Case(
                    case_id=row[idx["ID"]],
                    layer=layer,
                    requirement=row[idx["Requirement ID"]],
                    design_ref=row[idx["Design Ref"]],
                    title=row[idx["Title"]],
                    objective=row[idx["Objective"]],
                    expected=row[idx["Expected Result"]],
                    design_automation=row[idx["Automation"]],
                    priority=row[idx["Priority"]],
                )
            )
    return cases


def load_map() -> dict[str, tuple[list[str], str]]:
    if not CASE_MAP.exists():
        return {}
    out: dict[str, tuple[list[str], str]] = {}
    with CASE_MAP.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            cid = (row.get("case_id") or "").strip()
            if not cid:
                continue
            tests = [t.strip() for t in (row.get("rust_tests") or "").split(";") if t.strip()]
            out[cid] = (tests, (row.get("note") or "").strip())
    return out


def parse_run(run_dir: Path) -> RunResult:
    result = RunResult()
    if not run_dir.is_dir():
        return result
    for log in sorted(run_dir.glob("*.log")):
        gate = log.stem
        for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.rstrip()
            m = RESULT.match(line)
            if m:
                name = m.group("name").strip()
                verdict = m.group("verdict").strip()
                result.ran.add(name)
                # `ignored` is its own outcome, not a failure. One test is
                # deliberately parked behind a live Docker daemon (ADR-011);
                # counting it as failed made the summary claim "1 failed" while
                # every gate exited 0, which teaches the reader to distrust the
                # whole matrix. `filtered out` is a filter, not a result.
                if verdict.startswith("ignored"):
                    result.ignored.add(name)
                elif verdict.startswith("ok"):
                    result.passed.add(name)
                else:
                    result.failed[name] = verdict
                continue
            m = SUMMARY.match(line)
            if m:
                # A non-zero summary for this gate is the authoritative signal;
                # the exit code is written by the runner next to the log.
                pass
    for code_file in sorted(run_dir.glob("*.exit")):
        gate = code_file.stem
        result.gate_exit[gate] = int(code_file.read_text(encoding="utf-8").strip() or "-1")
    return result


def match_test(pattern: str, result: RunResult) -> tuple[str, list[str]]:
    """Resolve a mapping entry to actual outcomes.

    A mapping entry is a cargo test filter: a substring of the full test path.
    Substring matching is what cargo itself does, so an entry that matches
    several tests is not an error -- it is a deliberately broad filter. The
    caller sees every match, which is why a typo shows up as zero matches
    rather than as a silently passing case.
    """
    if pattern in result.passed:
        return "passed", [pattern]
    if pattern in result.failed:
        return "failed", [pattern]
    hits_p = sorted(t for t in result.passed if pattern in t)
    hits_f = sorted(t for t in result.failed if pattern in t)
    if hits_f:
        return "failed", hits_f
    if hits_p:
        return "passed", hits_p
    return "missing", []


def classify(case: Case, result: RunResult) -> tuple[str, list[str], str]:
    if not case.mapped:
        return ("MANUAL" if case.layer in MANUAL_LAYERS else "UNMAPPED"), [], case.note

    seen_pass: list[str] = []
    seen_fail: list[str] = []
    missing: list[str] = []
    for pattern in case.mapped:
        state, hits = match_test(pattern, result)
        if state == "passed":
            seen_pass.extend(hits)
        elif state == "failed":
            seen_fail.extend(hits)
        else:
            missing.append(pattern)

    evidence = sorted(set(seen_pass + seen_fail))
    if seen_fail:
        return "FAIL", evidence, case.note
    if missing and seen_pass:
        return "PARTIAL", evidence, case.note
    if missing and not seen_pass:
        return "PARTIAL", evidence, case.note
    # Everything mapped ran and passed. A UAT case still needs a human in a real
    # environment; the tests only prove the machine-checkable contract.
    if case.layer in MANUAL_LAYERS:
        return "MANUAL", evidence, case.note
    return "PASS", evidence, case.note


def main() -> int:
    run_name = sys.argv[1] if len(sys.argv) > 1 else None
    run_dir = EVIDENCE_DIR / "runs" / run_name if run_name else latest_run(EVIDENCE_DIR)
    if run_dir is None:
        print("no run directory under mock/evidence/runs; run run_regression.ps1 first",
              file=sys.stderr)
        return 2

    cases = load_cases()
    mapping = load_map()
    for case in cases:
        if case.case_id in mapping:
            case.mapped, case.note = mapping[case.case_id]

    result = parse_run(run_dir)

    rows = []
    for case in cases:
        status, evidence, note = classify(case, result)
        rows.append(
            {
                "case_id": case.case_id,
                "layer": case.layer,
                "requirement": case.requirement,
                "design_ref": case.design_ref,
                "title": case.title,
                "priority": case.priority,
                "design_automation": case.design_automation,
                "status": status,
                "mapped_tests": ";".join(case.mapped),
                "executed_tests": ";".join(evidence),
                "note": note,
            }
        )

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    matrix = EVIDENCE_DIR / "coverage_matrix.csv"
    with matrix.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "case_id", "layer", "requirement", "design_ref", "title", "priority",
                "design_automation", "status", "mapped_tests", "executed_tests", "note",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    by_layer: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        by_layer[r["layer"]][r["status"]] += 1

    summary = {
        "run": run_dir.name,
        "total_cases": len(rows),
        "total_tests_executed": len(result.ran),
        "tests_passed": len(result.passed),
        "tests_failed": len(result.failed),
        "tests_ignored": len(result.ignored),
        "ignored_tests": sorted(result.ignored),
        "gate_exit": result.gate_exit,
        "by_layer": {k: dict(v) for k, v in by_layer.items()},
        "failing_cases": [r["case_id"] for r in rows if r["status"] == "FAIL"],
        "unmapped_cases": [r["case_id"] for r in rows if r["status"] in ("UNMAPPED", "PARTIAL")],
    }
    (EVIDENCE_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    missing = [k for k in REQUIRED_SUMMARY_KEYS if k not in summary]
    if missing:
        print(f"summary is missing {missing}; summary.json and REGRESSION.md must "
              f"agree on key names or the report silently stops being written",
              file=sys.stderr)
        return 2

    write_report(rows, summary)
    print(json.dumps(summary["by_layer"], indent=2))
    print(f"failing cases: {summary['failing_cases'] or 'none'}")
    return 1 if summary["failing_cases"] else 0


def latest_run(base: Path) -> Path | None:
    runs = base / "runs"
    if not runs.is_dir():
        return None
    candidates = sorted([p for p in runs.iterdir() if p.is_dir()])
    return candidates[-1] if candidates else None


def write_report(rows: list[dict], summary: dict) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SandTree 回归测试报告",
        "",
        f"- 运行标识：`{summary['run']}`",
        f"- 设计用例：{summary['total_cases']} 条（来自只读基线 `tests/test_cases.json`）",
        f"- 实际执行 Rust 测试：{summary['total_tests_executed']} 条"
        f"（通过 {summary['tests_passed']} / 失败 {summary['tests_failed']}"
        f" / 按设计挂起 {summary['tests_ignored']}）",
        "",
        "> 执行数按**去重后的测试名**统计，各 gate 汇报的 "
        "`test result: ok. N passed` 相加会略大于它：cargo 对集成测试只打印"
        "模块路径、不打印所属二进制，两个二进制里的同名测试在证据里会被并成一条。"
        "要按二进制区分，用 `mock/scripts/extract_test_inventory.py`。",
        "",
        "## 四道 Gate 结果",
        "",
        "| Gate | 用例数 | PASS | FAIL | PARTIAL | MANUAL | UNMAPPED |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for layer in LAYERS:
        c = summary["by_layer"].get(layer, {})
        total = sum(c.values())
        lines.append(
            f"| {layer} | {total} | {c.get('PASS', 0)} | {c.get('FAIL', 0)} | "
            f"{c.get('PARTIAL', 0)} | {c.get('MANUAL', 0)} | {c.get('UNMAPPED', 0)} |"
        )

    lines += ["", "## 状态含义", "",
              "| 状态 | 含义 |", "| --- | --- |",
              "| `PASS` | 映射到的测试全部执行且通过 |",
              "| `FAIL` | 至少一条映射测试执行且失败 |",
              "| `PARTIAL` | 部分映射测试未找到（映射有笔误或测试被改名） |",
              "| `MANUAL` | 该用例按设计需人工在真实环境验收；映射测试只覆盖机器可验部分 |",
              "| `UNMAPPED` | 设计基线里有这条用例，但本仓没有任何验证 |",
              "",
              "## 失败用例", ""]
    fails = [r for r in rows if r["status"] == "FAIL"]
    if not fails:
        lines.append("无。")
    else:
        lines += ["| 用例 | 需求 | 标题 | 失败的测试 |", "| --- | --- | --- | --- |"]
        for r in fails:
            lines.append(
                f"| `{r['case_id']}` | {r['requirement']} | {r['title']} | "
                f"`{r['executed_tests']}` |"
            )

    lines += ["", "## 按设计挂起的测试", ""]
    if summary["ignored_tests"]:
        lines += [
            "这些测试没有失败，是被 `#[ignore]` 主动移出默认门禁的（ADR-011："
            "唯一依赖活 Docker daemon 的那条）。列出它们，是为了让「没跑」和"
            "「按设计不跑」在证据里不是同一件事。",
            "",
        ]
        for name in summary["ignored_tests"]:
            lines.append(f"- `{name}`")
    else:
        lines.append("无。")

    lines += ["", "## 未验证 / 待人工", ""]
    open_rows = [r for r in rows if r["status"] in ("PARTIAL", "UNMAPPED", "MANUAL")]
    lines += ["| 用例 | 需求 | 标题 | 状态 | 说明 |", "| --- | --- | --- | --- | --- |"]
    for r in open_rows:
        note = r["note"] or ""
        lines.append(
            f"| `{r['case_id']}` | {r['requirement']} | {r['title']} | {r['status']} | {note} |"
        )

    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
