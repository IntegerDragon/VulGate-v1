from dataclasses import replace
import itertools
import json
import os
from pathlib import Path
import random
import subprocess

import pytest

from tools.verification.decisions import SearchLimit, solve
from tools.verification.engine import analyze, digest
from tools.verification.spec import Policy, SpecificationError, TablePolicy, Task
from tools.verification.synthesis import Sketch, synthesize, trace_nogood
from tools.verification.source import instrument
from tools.verification.toolchain import ProcessResult, Toolchain


CASES = Path(__file__).resolve().parent / "verification_cases"


@pytest.fixture
def toolchain():
    config = os.environ.get("VULGATE_TOOLCHAIN")
    if not config:
        pytest.skip("set VULGATE_TOOLCHAIN for real C synthesis tests")
    return Toolchain.load(config)


def test_finite_solver_matches_exhaustive_reference():
    randomizer = random.Random(319)
    for _ in range(120):
        sizes = [randomizer.randint(2, 4) for _ in range(3)]
        clauses = [tuple((v, randomizer.randrange(sizes[v])) for v in randomizer.sample(range(3), randomizer.randrange(4)))
                   for _ in range(randomizer.randrange(9))]

        def valid(assignment):
            return all(any(assignment[v] != value for v, value in clause) for clause in clauses)

        reference = [a for a in itertools.product(*(range(size) for size in sizes)) if valid(a)]
        actual, _ = solve(sizes, clauses)
        assert (actual is None) == (not reference)
        assert actual is None or valid(actual)


def test_decision_budget_is_unknown_not_unsat():
    with pytest.raises(SearchLimit):
        solve([2, 2], [((0, 0), (1, 0))], node_limit=1)


def test_tool_fingerprint_timeout_is_a_terminal_unknown_result(monkeypatch, tmp_path):
    task = make_task(tmp_path, 'void root(void) { __CPROVER_assert(1,"target"); }')
    toolchain = Toolchain("/tools", "Ubuntu-24.04")
    monkeypatch.setattr(Toolchain, "run", lambda self, name, args, timeout:
                        ProcessResult([], 0, f"{name} 6.11.0 (64-bit)", ""))

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", timeout)
    entry = TablePolicy("gate", task.sources[0], "root", (), (None,), (0,))
    report = synthesize(task, toolchain, Sketch((entry,)), tmp_path / "result")
    assert report["synthesis_status"] == "UNKNOWN" and not report["nogoods"]
    assert "fingerprint query timed out" in report["reasons"][0]
    assert json.loads((tmp_path / "result/status.json").read_text())["status"] == "COMPLETE"


def test_source_cannot_disable_required_backend_checks():
    with pytest.raises(SpecificationError, match="disables backend checks"):
        instrument(b'#pragma CPROVER check disable "div-by-zero"\nvoid root(void) {}', [], "root", True)


def test_real_preprocessed_check_disabling_is_unknown(toolchain, tmp_path):
    task = make_task(tmp_path, '''
#pragma CPROVER check disable "div-by-zero"
void root(void) { __CPROVER_assert(1,"target"); }
''')
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["status"] == "UNKNOWN"
    assert "disables backend checks" in report["reasons"][0]


@pytest.mark.parametrize("predicates,actions,decisions", [
    (({"const": True},), (-1,), (0,)),
    ((), (-1, -1), (0,)),
    ((), (-1,), (2,)),
    ((), (True,), (0,)),
])
def test_invalid_tables_are_rejected(tmp_path, predicates, actions, decisions):
    with pytest.raises(SpecificationError):
        TablePolicy("gate", tmp_path / "program.c", "operation", predicates, actions, decisions)


def test_policy_table_roundtrip(tmp_path):
    table = TablePolicy("gate", tmp_path / "program.c", "operation", ({"var": "x"},), (-1, -2), (0, 2))
    path = tmp_path / "policies.json"
    path.write_text(json.dumps({"schema": 1, "policies": [table.to_dict()]}), encoding="utf-8")
    assert Policy.load_many(path) == [table]


def test_trace_generalization_requires_complete_entry_decisions(tmp_path):
    table = TablePolicy("gate", tmp_path / "program.c", "operation", ({"var": "x"},), (-1,), (0, 1))
    qualification = {"policies": [{"policy_id": "gate", "compiled_functions": ["module::operation"]}]}
    trace = [
        {"stepType": "function-call", "function": {"identifier": "module::operation"}},
        {"stepType": "assignment", "lhs": "__vulgate_region_gate", "value": {"binary": "1"}},
        {"stepType": "assignment", "lhs": "__vulgate_decision_gate", "value": {"binary": "1"}},
        {"stepType": "failure"},
    ]
    clause, details = trace_nogood({"trace": trace}, [table], qualification)
    assert clause == ((1, 1),) and details["method"] == "decision_prefix"
    for incomplete in (trace[1:], [trace[0], trace[-1]], trace[:-1]):
        clause, details = trace_nogood({"trace": incomplete}, [table], qualification)
        assert clause == ((0, 0), (1, 1)) and details["method"] == "full_candidate"


def make_task(tmp_path, program):
    source = tmp_path / "program.c"
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                      'extern void __CPROVER_assume(_Bool);\n' + program, encoding="utf-8")
    return Task(tmp_path / "task.json", (source,), "root", ("target",), timeout=30)


def test_real_synthesis_uses_compiler_counterexamples(toolchain, tmp_path):
    task = Task.load(CASES / "scalar_target/task.json")
    sketch = Sketch.load(CASES / "scalar_target/sketch.json")
    report = synthesize(task, toolchain, sketch, tmp_path / "result")
    assert report["synthesis_status"] == "SOLVED_FOR_HARNESS", report
    assert len(report["rounds"]) == 2
    assert report["rounds"][0]["feedback"][0]["method"] == "decision_prefix"
    policies = Policy.load_many(report["accepted_policies"]["path"])
    assert policies[0].decisions == (0, 1)
    final = json.loads(Path(report["accepted_policies"]["verification"]).read_text(encoding="utf-8"))
    assert final["actions"][0]["cache_hit"]
    assert final["pass_preservation"]["status"] == "PROVED_FOR_HARNESS"
    assert not report["deployment_ready"]
    # A previous timeout/unsupported result must not permanently suppress a
    # fresh action query when a later synthesis/verification run can complete.
    cache_file = next((tmp_path / "result/action_cache").glob("*.json"))
    envelope = json.loads(cache_file.read_text(encoding="utf-8"))
    envelope["payload"]["query"]["completeness"] = "UNKNOWN"
    envelope["sha256"] = digest(envelope["payload"])
    cache_file.write_text(json.dumps(envelope), encoding="utf-8")
    retried = analyze(task, toolchain, policies, tmp_path / "retry", action_cache=tmp_path / "result/action_cache")
    assert not retried["actions"][0]["cache_hit"]


def test_real_unobservable_conflict_is_infeasible(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern _Bool nondet_bool(void);
int operation(_Bool hidden) { __CPROVER_assert(!hidden,"target"); return 0; }
void root(void) {
    _Bool hidden=nondet_bool();
    int rc=operation(hidden);
    __CPROVER_assert(hidden || rc==0,"contract.normal_completion");
}
''')
    table = TablePolicy("gate", task.sources[0], "operation", (), (-1,), (0,))
    report = synthesize(task, toolchain, Sketch((table,), max_rounds=4), tmp_path / "result")
    assert report["synthesis_status"] == "INFEASIBLE_FOR_SKETCH", report
    assert report["accepted_policies"] is None
    assert len(report["rounds"]) == 2


def test_real_observation_refinement_and_return_action_selection(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern unsigned nondet_uint(void);
int operation(unsigned mode) { __CPROVER_assert(mode==0,"target"); return 0; }
void root(void) {
    unsigned mode=nondet_uint(); __CPROVER_assume(mode<=2);
    int rc=operation(mode);
    __CPROVER_assert(mode==0 ? rc==0 : (mode==1 ? rc==-1 : rc==-2),"contract.result");
}
''')
    basis = tuple({"op": "==", "args": [{"var": "mode"}, {"const": n}]} for n in (1, 2))
    table = TablePolicy("gate", task.sources[0], "operation", basis, (-1, -2), (0, 0, 0, 0))
    report = synthesize(task, toolchain, Sketch((table,), max_rounds=10), tmp_path / "result")
    assert report["synthesis_status"] == "SOLVED_FOR_HARNESS", report
    accepted = Policy.load_many(report["accepted_policies"]["path"])[0]
    assert accepted.decisions[:3] == (0, 1, 2)


def test_real_round_limit_and_incomplete_execution_remain_unknown(toolchain, tmp_path):
    task = Task.load(CASES / "scalar_target/task.json")
    sketch = replace(Sketch.load(CASES / "scalar_target/sketch.json"), max_rounds=1)
    report = synthesize(task, toolchain, sketch, tmp_path / "limited")
    assert report["synthesis_status"] == "UNKNOWN"
    assert report["reasons"] == ["synthesis round limit reached"]
    source = make_task(tmp_path, '''
extern int external(int);
int operation(int value) { return external(value); }
void root(void) { int rc=operation(0); __CPROVER_assert(rc==0,"target"); }
''')
    table = TablePolicy("gate", source.sources[0], "operation", (), (-1,), (0,))
    unknown = synthesize(source, toolchain, Sketch((table,)), tmp_path / "incomplete")
    assert unknown["synthesis_status"] == "UNKNOWN" and not unknown["nogoods"]


def test_real_refusal_changes_later_observation_region(toolchain, tmp_path):
    task = make_task(tmp_path, '''
int state;
int step(int event) { __CPROVER_assert(event==0,"target"); return 0; }
void root(void) {
    int first=step(1);
    if(first<0) state=1;
    int second=step(0);
    __CPROVER_assert(!state || second==0,"contract.retry_completion");
}
''')
    table = TablePolicy("gate", task.sources[0], "step", ({"var": "state"},), (-1,), (0, 0))
    report = synthesize(task, toolchain, Sketch((table,)), tmp_path / "result")
    assert report["synthesis_status"] == "SOLVED_FOR_HARNESS", report
    accepted = Policy.load_many(report["accepted_policies"]["path"])[0]
    assert accepted.decisions == (1, 0)
    regions = report["accepted_policies"]["conditional_actions"]
    assert [region["reachability"] for region in regions] == ["REACHABLE", "REACHABLE"]


def test_real_two_entries_are_synthesized_as_one_program(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern unsigned nondet_uint(void);
int prepare(unsigned count) { __CPROVER_assert(count<=1,"target.prepare"); return 0; }
int finish(unsigned count) { __CPROVER_assert(count==0,"target.finish"); return 0; }
void root(void) {
    unsigned count=nondet_uint(); __CPROVER_assume(count<4);
    if(prepare(count)<0) {
        __CPROVER_assert(count!=0,"contract.normal_completion");
        return;
    }
    int rc=finish(count);
    __CPROVER_assert(count!=0 || rc==0,"contract.normal_completion");
}
''')
    task = replace(task, targets=("target.prepare", "target.finish"))
    first = TablePolicy("first", task.sources[0], "prepare",
                        ({"op": ">", "args": [{"var": "count"}, {"const": 1}]},), (-1,), (0, 0))
    second = TablePolicy("second", task.sources[0], "finish",
                         ({"op": "==", "args": [{"var": "count"}, {"const": 1}]},), (-1,), (0, 0))
    report = synthesize(task, toolchain, Sketch((first, second)), tmp_path / "result")
    assert report["synthesis_status"] == "SOLVED_FOR_HARNESS", report
    accepted = Policy.load_many(report["accepted_policies"]["path"])
    assert [p.decisions for p in accepted] == [(0, 1), (0, 1)]
    feedback = [item for round in report["rounds"] for item in round["feedback"]]
    assert any(len({event["entry"] for event in item["events"]}) == 2 for item in feedback)


@pytest.mark.parametrize("action,expected", [(None, "SOLVED_FOR_HARNESS"), (0, "UNKNOWN")])
def test_real_void_return_type_binding(toolchain, tmp_path, action, expected):
    task = make_task(tmp_path, '''
extern _Bool nondet_bool(void);
void operation(_Bool skip) { __CPROVER_assert(!skip,"target"); }
void root(void) { operation(nondet_bool()); }
''')
    table = TablePolicy("gate", task.sources[0], "operation", ({"var": "skip"},), (action,), (0, 0))
    report = synthesize(task, toolchain, Sketch((table,)), tmp_path / "result")
    assert report["synthesis_status"] == expected, report
    if expected == "UNKNOWN":
        assert not report["nogoods"]
