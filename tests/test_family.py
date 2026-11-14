from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.engine import analyze
from tools.verification.family import expand_family, family_status, seed_family
from tools.verification.shadow import private_havoc_target
from tools.verification.source import family_state, instrument
from tools.verification.spec import FamilyPolicy, Policy, SpecificationError, TablePolicy, Task
from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get("VULGATE_TOOLCHAIN")
    if not config:
        pytest.skip("set VULGATE_TOOLCHAIN for policy-family integration tests")
    return Toolchain.load(config)


def policy(source, *, domains=((1, 2),), selection="fixed_table", function="operation", predicates=(), returns=(-1, -2), name="gate"):
    return FamilyPolicy(name, source, function, predicates, returns, domains, selection)


@pytest.mark.parametrize("domains", [(), ((),), ((1, 1),), ((3,),), ((True,),), (({},),)])
def test_family_domains_are_nonempty_and_typed(tmp_path, domains):
    with pytest.raises(SpecificationError):
        policy(tmp_path / "program.c", domains=domains)


def test_family_policy_roundtrip_and_seed_conversion(tmp_path):
    p = policy(tmp_path / "program.c", selection="per_invocation")
    file = tmp_path / "policies.json"
    file.write_text(json.dumps({"schema": 1, "policies": [p.to_dict()]}), encoding="utf-8")
    assert Policy.load_many(file) == [p]
    guard = Policy("gate", p.translation_unit, "operation", -1, {"var": "bad"})
    assert seed_family(guard).domains == ((0,), (1,))
    assert seed_family(p).selection == "per_invocation"
    assert seed_family(p, "fixed_table").selection == "fixed_table"


def test_generated_family_choices_do_not_assume_original_inputs(tmp_path):
    fixed = policy(tmp_path / "program.c")
    state = family_state([fixed])
    assert "__CPROVER_assume" not in state
    assert "if (__vulgate_family_initialized) return;" in state
    assert "% 2u" in state
    code, _, _ = instrument(b'int operation(void){return 0;} void root(void){operation();}',
                             [fixed], "root", True, initialize_family=True)
    assert b"__vulgate_family_initialize();" in code
    assert b"__VG_REACH_ACTION:gate:0:2" in code
    fresh, _, _ = instrument(b'int operation(void){return 0;}', [replace(fixed, selection="per_invocation")], "root", False)
    assert b"__CPROVER_havoc_object(&__vulgate_sample_gate)" in fresh
    assert b"__CPROVER_assume" not in fresh.split(b"int operation")[1]


def test_private_choice_havoc_cannot_be_redirected_to_user_storage():
    kind = {"id": "unsignedbv", "namedSub": {"width": {"id": "32"}}}
    variable = {"id": "symbol", "namedSub": {"identifier": {"id": "f::sample"}, "type": kind}}
    instruction = {"instructionId": "OTHER", "code": {"namedSub": {"statement": {"id": "havoc_object"}},
        "sub": [{"id": "address_of", "sub": [variable]}]}}
    symbols = {"f::sample": {"baseName": "__vulgate_sample_gate", "isStaticLifetime": False}}
    assert private_havoc_target(instruction, symbols, "__vulgate_sample_gate") == variable
    symbols["f::sample"]["isStaticLifetime"] = True
    assert private_havoc_target(instruction, symbols) is None
    symbols["f::sample"].update(baseName="caller_output", isStaticLifetime=False)
    assert private_havoc_target(instruction, symbols) is None


def make_task(tmp_path, body, targets=("target",)):
    source = tmp_path / "program.c"
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                      'extern void __CPROVER_assume(_Bool);\n' + body, encoding="utf-8")
    return Task(tmp_path / "task.json", (source,), "root", targets, unwind=8, timeout=45)


@pytest.mark.parametrize("selection,expected", [("fixed_table", "PROVED_FOR_HARNESS"), ("per_invocation", "REFUTED")])
def test_real_choice_lifetime_matters_across_recursive_root_calls(toolchain, tmp_path, selection, expected):
    task = make_task(tmp_path, '''
int previous,depth;
int operation(void) { __CPROVER_assert(0,"target"); return 0; }
void root(void) {
    int value=operation();
    if(depth==0) { previous=value; depth=1; root(); }
    else __CPROVER_assert(value==previous,"contract.stable_return");
}
''')
    report = analyze(task, toolchain, [policy(task.sources[0], selection=selection)], tmp_path / "result")
    assert report.get("family", {}).get("contract_status") == expected, report
    assert report["family"]["policy_status"] == expected
    assert report["protected"]["initialization"] == "PROVED_FOR_HARNESS"
    if selection == "fixed_table":
        assert report["pass_preservation"]["status"] == "PROVED_FOR_HARNESS"
        assert all(r["contract_domain_status"] == "QUALIFIED_WITH_JOINT_FAMILY" for r in report["family"]["conditional_domains"])


def test_real_family_separates_contract_domains_from_target_coverage(toolchain, tmp_path):
    task = make_task(tmp_path, '''
int operation(void) { __CPROVER_assert(0,"target"); return 0; }
void root(void) { int rc=operation(); __CPROVER_assert(rc>=-2,"contract.return_range"); }
''')
    report = analyze(task, toolchain, [policy(task.sources[0], domains=((0, 1, 2),), selection="per_invocation")], tmp_path / "result")
    assert report["family"]["contract_status"] == "PROVED_FOR_HARNESS", report
    assert report["family"]["policy_status"] == "REFUTED"
    assert report["protected"]["target"] == "REFUTED"


@pytest.mark.parametrize("selection", ["fixed_table", "per_invocation"])
def test_real_void_family_cannot_skip_caller_output_initialization(toolchain, tmp_path, selection):
    task = make_task(tmp_path, '''
void operation(int *out) { *out=1; __CPROVER_assert(1,"target"); }
void root(void) { int output; operation(&output); __CPROVER_assert(output==1,"contract.output"); }
''')
    report = analyze(task, toolchain, [policy(task.sources[0], domains=((0, 1),), returns=(None,), selection=selection)], tmp_path / "result")
    assert report["protected"]["initialization"] == "REFUTED", report
    assert report["family"]["contract_status"] == "REFUTED"


@pytest.mark.parametrize("selection,expected", [("fixed_table", ((0,), (1, 2))), ("per_invocation", ((0,), (1,)))])
def test_real_expansion_qualifies_alternative_returns_in_their_region(toolchain, tmp_path, selection, expected):
    fixture = Path(__file__).parent / "verification_cases/policy_family"
    task = Task.load(fixture / "task.json")
    seeds = Policy.load_many(fixture / "seed.json")
    report = expand_family(task, toolchain, seeds, tmp_path / "result", selection=selection)
    assert report["family_expansion_status"] == "MAXIMAL_FOR_SEED", report
    exported = Policy.load_many(report["accepted_family"]["path"])
    assert exported[0].domains == expected
    assert len(report["queries"]) == 5
    assert report["accepted_family"]["family_evidence"]["policy_status"] == "PROVED_FOR_HARNESS"


def test_real_expansion_does_not_merge_incompatible_marginal_choices(toolchain, tmp_path):
    task = make_task(tmp_path, '''
int left(void) { __CPROVER_assert(0,"left.target"); return 0; }
int right(void) { __CPROVER_assert(0,"right.target"); return 0; }
void root(void) { int a=left(),b=right(); __CPROVER_assert(a==0 || b==0,"contract.one_completes"); }
''', targets=("left.target", "right.target"))
    seeds = [TablePolicy(name, task.sources[0], name, (), (0, -1), (1,)) for name in ("left", "right")]
    report = expand_family(task, toolchain, seeds, tmp_path / "result")
    assert report["family_expansion_status"] == "MAXIMAL_FOR_SEED", report
    exported = Policy.load_many(report["accepted_family"]["path"])
    assert [p.domains for p in exported] == [((1, 2),), ((1,),)]
    assert report["queries"][-1]["addition"] == {"entry": "right", "region": 0, "choice": 2}
    assert report["queries"][-1]["status"] == "REFUTED"


def fake_result(policies, status="PROVED_FOR_HARNESS", dependencies="stable"):
    return {"dependencies_sha256": dependencies, "protected": {"completeness": "COMPLETE_FOR_HARNESS",
             "initialization": "PROVED_FOR_HARNESS", "contracts_and_runtime_checks": status, "target": "PROVED_FOR_HARNESS"},
            "pass_preservation": {"status": "PROVED_FOR_HARNESS", "qualification": {
                "policies": [{"status": "QUALIFIED_STRUCTURE"} for p in policies]}},
            "nonvacuity": {"status": "ESTABLISHED_FOR_HARNESS"}, "family": {"contract_status": status}}


@pytest.mark.parametrize("mode,expected", [("budget", "QUALIFIED_PARTIAL"), ("unknown", "QUALIFIED_PARTIAL"),
                                          ("changed", "UNKNOWN"), ("missing", "UNKNOWN")])
def test_expansion_budget_unknown_and_changed_dependencies_are_not_maximal(monkeypatch, tmp_path, mode, expected):
    from tools.verification import engine
    calls = []

    def evaluate(task, toolchain, policies, output, **kwargs):
        calls.append(policies)
        status = "UNKNOWN" if len(calls)>1 and mode=="unknown" else "PROVED_FOR_HARNESS"
        dependencies = None if mode=="missing" else "changed" if len(calls)>1 and mode=="changed" else "stable"
        return fake_result(policies, status, dependencies)

    monkeypatch.setattr(engine, "analyze", evaluate)
    seed = TablePolicy("gate", tmp_path / "program.c", "operation", (), (-1,), (1,))
    task = Task(tmp_path / 'task.json', (tmp_path / 'program.c',), 'root', ('target',))
    result = expand_family(task, None, [seed], tmp_path / "result", max_queries=1 if mode=="budget" else 4)
    assert result["family_expansion_status"] == expected
    assert (result["accepted_family"] is None) == (mode in ("changed", "missing"))


def test_family_does_not_promote_incomplete_semantics():
    report = fake_result([None], "REFUTED")
    report["protected"]["completeness"] = "UNKNOWN"
    assert family_status(report, "contracts") == "UNKNOWN"
