from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.lifecycle import Lifecycle, header_digest, state_leaves, verify_lifecycle
from tools.verification.spec import FamilyPolicy, Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain


CASES = Path(__file__).parent / "verification_cases/lifecycle"


@pytest.fixture
def toolchain():
    config = os.environ.get("VULGATE_TOOLCHAIN")
    if not config:
        pytest.skip("set VULGATE_TOOLCHAIN for lifecycle integration tests")
    return Toolchain.load(config)


def field(name):
    return {"base": {"var": "state"}, "field": name, "pointer": False}


@pytest.mark.parametrize("changes", [
    {"state_type": "struct S; int injected"},
    {"step": "initialize_work"},
    {"invariant": {"var": "hidden_global"}},
    {"rank": None},
    {"active": None},
])
def test_lifecycle_contract_rejects_ambiguous_or_unframed_inputs(changes):
    with pytest.raises(SpecificationError):
        replace(Lifecycle.load(CASES / "contract.json"), **changes)


@pytest.mark.parametrize("kind", ["pointer", "union", "floatbv", "c_bit_field"])
def test_persistent_state_requires_a_supported_complete_object(kind):
    with pytest.raises(SpecificationError):
        state_leaves({"id": kind}, {})


def test_header_binding_ignores_generated_line_paths_but_not_header_contents():
    prefix = b'struct State { unsigned count; };\n'
    suffix = b'typedef int vulgate_lifecycle_header_end;\nvoid root(void) {}'
    first = b'# 1 "one.c"\n' + prefix + b'# 2 "one.c"\n' + suffix
    second = b'# 1 "two.c"\n' + prefix + b'# 2 "two.c"\n' + suffix
    assert header_digest(first) == header_digest(second)
    assert header_digest(first) != header_digest(second.replace(b'unsigned count', b'unsigned changed'))


def make_case(tmp_path, initialize, step, *, members="unsigned remaining; unsigned budget;", extra="", invariant=None, progress=True):
    header = tmp_path / "state.h"
    header.write_text(f'struct State {{ {members} }};\n', encoding="utf-8")
    source = tmp_path / "program.c"
    source.write_text('#include "state.h"\nextern void __CPROVER_assert(_Bool,const char*);\n'
                      'extern void __CPROVER_assume(_Bool);\nextern unsigned nondet_uint(void);\n' + extra +
                      f'\nvoid initialize(struct State *state) {{ {initialize} }}\n'
                      f'void event(struct State *state) {{ {step} }}\n'
                      'void root(void) { struct State state; initialize(&state); event(&state); }\n', encoding="utf-8")
    task = Task(tmp_path / "task.json", (source,), "root", ("target",), unwind=4, timeout=60)
    invariant = invariant or {"op": "<=", "args": [field("remaining"), field("budget")]}
    contract = Lifecycle(header, "struct State", "initialize", "event", invariant,
                         {"op": ">", "args": [field("remaining"), {"const": 0}]} if progress else None,
                         field("remaining") if progress else None)
    return task, contract


@pytest.mark.parametrize("selection", ["guard", "fixed_table", "per_invocation"])
def test_real_induction_and_descent_use_arbitrary_compiled_state(toolchain, tmp_path, selection):
    task = Task.load(CASES / "task.json")
    contract = Lifecycle.load(CASES / "contract.json")
    policies = Policy.load_many(CASES / "policies.json")
    if selection != "guard":
        p = policies[0]
        policies = [FamilyPolicy(p.name, p.translation_unit, p.function, (p.guard,), (-1,), ((0,), (1,)), selection)]
    report = verify_lifecycle(task, toolchain, contract, policies, tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "PROVED_DESCENT", report
    assert report["state_audit"]["state_leaves"] == ["(state).remaining", "(state).budget"]
    assert set(report["phases"]) == {"initiation", "consecution", "progress"}
    source = (Path(report["run"]) / "consecution.c").read_text(encoding="utf-8")
    assert "state = nondet_vulgate_lifecycle_state()" in source
    assert "for (" not in source and "while (" not in source
    assert report["status"] == "UNKNOWN" and not report["deployment_ready"]


def test_real_initializer_must_define_every_persistent_field(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=0;', '__CPROVER_assert(1,"target");',
                               invariant={"const": True}, progress=False)
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "INITIATION_REFUTED", report
    verification = json.loads(Path(report["phases"]["initiation"]["verification"]).read_text())
    assert verification["protected"]["initialization"] == "REFUTED"


def test_real_noninductive_state_is_not_reported_as_an_actual_execution_failure(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=0; state->budget=1;',
                               'state->remaining++; __CPROVER_assert(1,"target");', progress=False)
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "NOT_INDUCTIVE", report
    assert report["status"] == "UNKNOWN"
    assert "unreachable invariant state" in report["scope"]


def test_real_early_return_can_preserve_safety_but_refute_ranking(toolchain, tmp_path):
    task = Task.load(CASES / "task.json")
    contract = Lifecycle.load(CASES / "contract.json")
    policies = [Policy("stall", task.sources[0], "process_event", None, {"const": True})]
    report = verify_lifecycle(task, toolchain, contract, policies, tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "RANKING_REFUTED", report


@pytest.mark.parametrize("reference", ["body", "policy"])
def test_real_mutable_globals_cannot_disappear_between_events(toolchain, tmp_path, reference):
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;',
                               ('hidden++;' if reference == "body" else '') + '__CPROVER_assert(1,"target");',
                               extra='unsigned hidden;')
    policies = [Policy("guard", task.sources[0], "event", None, {"var": "hidden"})] if reference == "policy" else []
    report = verify_lifecycle(task, toolchain, contract, policies, tmp_path / "result")
    assert report["lifecycle_status"] == "UNKNOWN"
    assert any("outside state: hidden" in reason for reason in report["reasons"]), report
    assert not report["phases"]


def test_real_nondeterministic_pointers_are_not_closed_state_inputs(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;',
                               'int *unused=nondet_object(); __CPROVER_assert(1,"target");',
                               extra='extern int *nondet_object(void);')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "UNKNOWN"
    assert any("nondeterministic object" in reason for reason in report["reasons"]), report


def test_real_persistent_pointers_need_a_separate_heap_contract(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=0;state->budget=0;state->object=0;',
                               '__CPROVER_assert(1,"target");', members='unsigned remaining,budget; int *object;')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "UNKNOWN"
    assert any("pointer" in reason for reason in report["reasons"]), report


def test_real_event_assumptions_do_not_prove_total_progress(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=2;state->budget=2;',
                               '__CPROVER_assume(state->remaining>0); state->remaining--; __CPROVER_assert(1,"target");')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "UNKNOWN"
    assert report["state_audit"]["environment_assumptions"]


def test_real_initial_input_constraints_do_not_prune_event_progress(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->budget=nondet_uint(); __CPROVER_assume(state->budget<=1000000); state->remaining=state->budget;',
                               'if(state->remaining)state->remaining--; __CPROVER_assert(1,"target");')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "PROVED_DESCENT"
    assert report["state_audit"]["environment_assumptions"] and not report["state_audit"]["event_assumptions"]


def test_real_incomplete_event_execution_is_not_an_inductive_proof(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=2;state->budget=2;',
                               'while(state->remaining) {} __CPROVER_assert(1,"target");')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == report["progress_status"] == "UNKNOWN", report
    verification = json.loads(Path(report["phases"]["consecution"]["verification"]).read_text())
    assert verification["protected"]["completeness"] == "UNKNOWN"


def test_real_arrays_and_local_aliases_are_part_of_persistent_state(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=2;state->budget=2;state->slots[0]=0;state->slots[1]=0;',
                               'unsigned *slot=&state->slots[0]; *slot=1; if(state->remaining)state->remaining--;'
                               '__CPROVER_assert(state->slots[0]==1,"target");',
                               members='unsigned remaining,budget; unsigned slots[2];')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "PROVED_DESCENT"
    assert len(report["state_audit"]["state_leaves"]) == 4


def test_real_enum_and_padding_use_logical_fields_for_initialization(toolchain, tmp_path):
    task, contract = make_case(tmp_path, "state->mode=IDLE;state->label='a';state->remaining=2;state->budget=2;",
                               'state->mode=ACTIVE; if(state->remaining)state->remaining--; __CPROVER_assert(1,"target");',
                               members='enum {IDLE,ACTIVE} mode; char label; unsigned remaining,budget;')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "PROVED_DESCENT"
    assert len(report["state_audit"]["state_leaves"]) == 4


def test_real_header_change_invalidates_the_entire_induction(monkeypatch, toolchain, tmp_path):
    from tools.verification import lifecycle as module
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;',
                               'if(state->remaining)state->remaining--; __CPROVER_assert(1,"target");')
    analyze = module.analyze

    def changing(*args, **kwargs):
        result = analyze(*args, **kwargs)
        if Path(args[3]).name == "initiation":
            with contract.header.open("a", encoding="utf-8") as file:
                file.write('\nstatic const unsigned changed_header = 3;\n')
        return result

    monkeypatch.setattr(module, "analyze", changing)
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == report["progress_status"] == "UNKNOWN", report
    assert any("dependencies changed" in reason for reason in report["reasons"]), report


def test_real_header_macros_cannot_rewrite_generated_proof_code(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;',
                               'if(state->remaining)state->remaining--; __CPROVER_assert(1,"target");')
    with contract.header.open("a", encoding="utf-8") as file:
        file.write('\n#define vulgate_lifecycle_observe(value) consumed()\n')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "UNKNOWN"
    assert any("harness changed during preprocessing" in reason for reason in report["reasons"]), report
    assert not report["phases"]


@pytest.mark.parametrize("moment", ["before", "after"])
def test_real_generated_sources_remain_bound_to_the_generator(monkeypatch, toolchain, tmp_path, moment):
    from tools.verification import lifecycle as module
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;',
                               'if(state->remaining)state->remaining--; __CPROVER_assert(1,"target");')
    analyze = module.analyze

    def edit(source):
        text = source.read_text(encoding="utf-8")
        source.write_text(text.replace('void vulgate_lifecycle_root(void) {',
                                      'void vulgate_lifecycle_root(void) { int bookkeeping=0;'), encoding="utf-8")

    def changing(derived, toolchain, policies, output):
        if moment == "before":
            edit(derived.sources[-1])
        result = analyze(derived, toolchain, policies, output)
        if moment == "after":
            edit(derived.sources[-1])
        return result

    monkeypatch.setattr(module, "analyze", changing)
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == report["progress_status"] == "UNKNOWN", report
    assert any("generated lifecycle" in reason and "changed" in reason for reason in report["reasons"]), report


@pytest.mark.parametrize("body", [
    'union {unsigned word; unsigned char byte;} value; value.word=1;',
    'unsigned char *bytes=(unsigned char*)&state->remaining;',
])
def test_real_object_representation_views_need_additional_frame_evidence(toolchain, tmp_path, body):
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;', body + '__CPROVER_assert(1,"target");')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "UNKNOWN"
    assert any("representation" in reason or "reinterpretation" in reason for reason in report["reasons"]), report


def test_real_fresh_local_allocations_are_discharged_per_event(toolchain, tmp_path):
    task, contract = make_case(tmp_path, 'state->remaining=1;state->budget=1;',
                               'unsigned *p=malloc(sizeof(*p)); if(p){*p=1;__CPROVER_assert(*p==1,"target");free(p);}'
                               'if(state->remaining)state->remaining--;',
                               extra='extern void *malloc(unsigned long); extern void free(void *);')
    report = verify_lifecycle(task, toolchain, contract, [], tmp_path / "result")
    assert report["lifecycle_status"] == "PROVED_INDUCTIVELY", report
    assert report["progress_status"] == "PROVED_DESCENT"
