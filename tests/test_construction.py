from dataclasses import replace
import io
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from tools.verification.construction import Generator, construct, run_generator, verification_feedback
from tools.verification.discovery import DiscoveryOptions, constant_value, discover, parameter_leaves, translate
from tools.verification.engine import digest
from tools.verification.expression import compile_expression
from tools.verification.openai_generator import main as adapter_main, propose
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.synthesis import Sketch, synthesize
from tools.verification.toolchain import Toolchain


CASES = Path(__file__).resolve().parent / "verification_cases"


@pytest.fixture
def toolchain():
    config = os.environ.get("VULGATE_TOOLCHAIN")
    if not config:
        pytest.skip("set VULGATE_TOOLCHAIN for compiler-backed construction tests")
    return Toolchain.load(config)


def scalar(kind="signedbv", width=32):
    return {"id": kind, "namedSub": {"width": {"id": str(width)}}}


def node(kind, value_type, *operands, **named):
    return {"id": kind, "namedSub": {"type": value_type, **named}, "sub": list(operands)}


def test_typed_ir_constants_and_lossy_casts():
    minus_two = node("constant", scalar(), value={"id": "FFFFFFFE"})
    assert constant_value(minus_two) == -2
    assert constant_value(node("constant", scalar(), value={"id": "10"}, **{"#base": {"id": "10"}})) == 10
    assert constant_value(node("typecast", scalar("unsignedbv", 8), minus_two)) == 254
    assert constant_value(node("typecast", scalar("c_bool", 8), minus_two)) == 1
    variable = node("symbol", scalar(), identifier={"id": "f::x"})
    assert translate(node("typecast", scalar("unsignedbv"), variable), {"f::x": "x"}, {}) is None
    assert translate(node("typecast", scalar(width=64), variable), {"f::x": "x"}, {}) == ({"var": "x"}, [])


def test_nullable_struct_reads_are_guarded_and_volatile_fields_omitted():
    volatile = {"id": "unsignedbv", "namedSub": {"width": {"id": "32"}, "#volatile": {"id": "1"}}}
    struct = {"id": "struct", "namedSub": {"components": {"sub": [
        {"namedSub": {"name": {"id": "count"}, "type": scalar("unsignedbv")}},
        {"namedSub": {"name": {"id": "external"}, "type": volatile}},
    ]}}}
    pointer = {"id": "pointer", "sub": [struct]}
    leaves = list(parameter_leaves({"var": "request"}, pointer, {}, 2))
    assert len(leaves) == 2
    assert leaves[1][0]["field"] == "count"
    assert leaves[1][2] == [{"op": "!=", "args": [{"var": "request"}, {"const": 0}]}]
    for expression, _, _ in leaves:
        compile_expression(expression)


@pytest.mark.parametrize("options", [{"max_entries": 17}, {"max_predicates": 9}, {"max_distance": 0}, {"field_depth": True}])
def test_invalid_discovery_limits(options):
    with pytest.raises(SpecificationError):
        DiscoveryOptions(**options)


def make_generator(tmp_path, program, **options):
    script = tmp_path / "adapter.py"
    script.write_text(program, encoding="utf-8")
    return Generator((sys.executable, str(script)), tmp_path, **options)


def test_generator_protocol_binds_response_to_request(tmp_path):
    generator = make_generator(tmp_path, 'import json,sys\nr=json.load(sys.stdin)\n'
        'print(json.dumps({"schema":1,"request_id":r["request_id"],"sketch":{"schema":1,"entries":[]}}))\n')
    request = {"schema": 1, "kind": "test", "text": "字段和空格"}
    response = run_generator(generator, request, tmp_path / "run")
    assert response == {"schema": 1, "entries": []}
    saved = json.loads((tmp_path / "run/request.json").read_text(encoding="utf-8"))
    assert saved["request_id"] == digest(request)
    assert json.loads((tmp_path / "run/process.json").read_text(encoding="utf-8"))["returncode"] == 0


@pytest.mark.parametrize('qualification', ['qualified', 'indirect', 'build', 'execution', 'initialization'])
def test_generator_feedback_uses_only_qualified_counterexamples(tmp_path, qualification):
    query = {'status': 'REFUTED', 'completeness': 'COMPLETE_FOR_HARNESS', 'initialization': 'PROVED_FOR_HARNESS',
             'properties': [{'property': 'root.assertion.1', 'description': 'target', 'status': 'FAILURE'}]}
    if qualification in ('indirect', 'build'):
        query['indirect_call_targets' if qualification == 'indirect' else 'build_semantics'] = {'status': 'UNKNOWN'}
    elif qualification == 'execution':
        query['completeness'] = 'UNKNOWN'
    elif qualification == 'initialization':
        query['initialization'] = 'UNKNOWN'
    path = tmp_path / 'query.json'
    path.write_text(json.dumps({'protected': query}))
    result = verification_feedback({'synthesis_status': 'UNKNOWN', 'reasons': ['diagnostic'],
        'rounds': [{'decisions': [], 'feedback': ['query diagnostic'], 'verification': str(path)}]})
    assert bool(result['counterexamples']) == (qualification == 'qualified')
    assert result['rounds'][0]['feedback'] == ['query diagnostic']


@pytest.mark.parametrize("program,reason", [
    ('print("not JSON")', "UTF-8 JSON"),
    ('print(\'{"schema":1,"request_id":"stale","sketch":{}}\')', "identity"),
    ('print("x"*2048)', "byte limit"),
    ('import sys; sys.exit(3)', "process failed"),
])
def test_generator_invalid_outputs_do_not_become_policies(tmp_path, program, reason):
    generator = make_generator(tmp_path, program, max_output_bytes=1024)
    with pytest.raises(SpecificationError, match=reason):
        run_generator(generator, {"schema": 1}, tmp_path / "run")


def test_generator_timeout_is_recorded(tmp_path):
    generator = make_generator(tmp_path, 'import time; time.sleep(20)', timeout=1)
    with pytest.raises(SpecificationError, match="timed out"):
        run_generator(generator, {"schema": 1}, tmp_path / "run")
    assert json.loads((tmp_path / "run/process.json").read_text(encoding="utf-8"))["timed_out"]


def test_generator_configuration_resolves_directory_relative_to_file(tmp_path):
    file = tmp_path / "generator.json"
    file.write_text(json.dumps({"schema": 1, "command": [sys.executable, "adapter.py"],
                                "directory": ".", "max_attempts": 2}), encoding="utf-8")
    generator = Generator.load(file)
    assert generator.directory == tmp_path and generator.max_attempts == 2
    with pytest.raises(SpecificationError, match="shell script"):
        Generator(("adapter.cmd",), tmp_path)


def test_optional_responses_adapter_uses_structured_sketches(tmp_path):
    calls = []
    sketch = {"schema": 1, "max_rounds": 4, "solver_nodes": 100,
              "entries": [{"id": "gate", "translation_unit": str(tmp_path / "program.c"), "function": "operation",
                           "predicates": [{"var": "flag"}], "returns": [-1]}]}

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(status="completed", output=[], output_text=json.dumps(sketch))

    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    request = {"schema": 1, "kind": "vulgate.sketch_request", "request_id": "bound-request"}
    result = propose(client, request, "explicit-test-model", max_output_tokens=1234)
    assert result == {"schema": 1, "request_id": "bound-request", "sketch": sketch}
    assert calls[0]["model"] == "explicit-test-model" and calls[0]["store"] is False
    assert calls[0]["max_output_tokens"] == 1234
    assert calls[0]["text"]["format"]["strict"] and calls[0]["text"]["format"]["type"] == "json_schema"
    assert calls[0]["text"]["format"]["schema"]["$defs"]["expression"]["anyOf"]


@pytest.mark.parametrize("status,refusal,text", [
    ("incomplete", False, "{}"), ("failed", False, "{}"),
    ("completed", True, "{}"), ("completed", False, "not JSON"),
])
def test_responses_adapter_rejects_incomplete_or_unusable_output(status, refusal, text):
    response = SimpleNamespace(status=status, output=[SimpleNamespace(content=[SimpleNamespace(type="refusal")])] if refusal else [],
                               output_text=text)
    client = SimpleNamespace(responses=SimpleNamespace(create=lambda **kwargs: response))
    with pytest.raises(ValueError):
        propose(client, {"schema": 1, "kind": "vulgate.sketch_request", "request_id": "x"}, "explicit-test-model")


def test_responses_adapter_protocol_is_utf8_independent_of_windows_locale(monkeypatch):
    request = {"schema": 1, "kind": "vulgate.sketch_request", "request_id": "bound", "context": "中文注释"}
    sketch = {"schema": 1, "max_rounds": 1, "solver_nodes": 10,
              "entries": [{"id": "gate", "translation_unit": "C:/临时/程序.c", "function": "action", "predicates": [], "returns": [-1]}]}
    seen = []

    class Client:
        def __init__(self, **kwargs):
            self.responses = SimpleNamespace(create=self.create)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def create(self, **kwargs):
            seen.append(json.loads(kwargs["input"])["context"])
            return SimpleNamespace(status="completed", output=[], output_text=json.dumps(sketch))

    raw = io.BytesIO()
    stdin = io.TextIOWrapper(io.BytesIO(json.dumps(request, ensure_ascii=False).encode("utf-8")), encoding="cp1252")
    stdout = io.TextIOWrapper(raw, encoding="cp1252")
    with monkeypatch.context() as patch:
        patch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=Client))
        patch.setattr(sys, "stdin", stdin)
        patch.setattr(sys, "stdout", stdout)
        assert adapter_main(["--model", "explicit-test-model"]) == 0
    assert seen == ["中文注释"]
    assert json.loads(raw.getvalue().decode("utf-8"))["sketch"] == sketch


def make_task(tmp_path, program):
    source = tmp_path / "program.c"
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'
                      'extern void __CPROVER_assume(_Bool);\n' + program, encoding="utf-8")
    return Task(tmp_path / "task.json", (source,), "root", ("target",), timeout=45)


def test_real_discovery_uses_compiler_fields_and_excludes_harness(toolchain, tmp_path):
    task = make_task(tmp_path, '''
struct Packet { unsigned length; volatile unsigned external; };
int inspect_packet(const struct Packet *p) {
    if (!p) return -2;
    __CPROVER_assert(p->length <= 7,"target"); return 0;
}
void root(void) { struct Packet p={1,0}; inspect_packet(&p); }
''')
    report = discover(task, toolchain, tmp_path / "result")
    assert report["discovery_status"] == "DISCOVERED", report
    assert [c["name"] for c in report["candidates"]] == ["inspect_packet"]
    candidate = report["candidates"][0]
    assert candidate["translation_unit"] == str(task.sources[0])
    assert candidate["returns"][:2] == [-2, -1]
    expressions = [compile_expression(p["expression"])[0] for p in candidate["predicates"]]
    assert any("length" in e and "&&" in e and "7" in e for e in expressions)
    assert not any("external" in e for e in expressions)
    assert any("root harness" in x["reason"] for x in report["excluded"])
    assert not report["deployment_ready"]


def test_real_automatic_basis_refinement_handles_distinct_error_actions(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern _Bool nondet_bool(void);
int dispatch(_Bool rejected, _Bool category) { __CPROVER_assert(!rejected,"target"); return 0; }
void root(void) {
    _Bool rejected=nondet_bool(), category=nondet_bool();
    int rc=dispatch(rejected,category);
    __CPROVER_assert(rejected ? rc==(category ? -2 : -1) : rc==0,"contract.result");
}
''')
    report = construct(task, toolchain, tmp_path / "result",
                       options=DiscoveryOptions(max_actions=4, max_predicates=4), max_rounds=12)
    assert report["construction_status"] == "SOLVED_FOR_HARNESS", report
    assert report["attempts"][0]["status"] == "INFEASIBLE_FOR_SKETCH"
    assert len(report["attempts"]) >= 2
    policies = Policy.load_many(report["accepted_policies"]["path"])
    assert any(-2 in policy.return_actions for policy in policies)


def test_real_discovery_keeps_static_symbols_in_separate_units(toolchain, tmp_path):
    a, b, harness = [tmp_path / name for name in ("a.c", "b.c", "root.c")]
    a.write_text('extern void __CPROVER_assert(_Bool,const char*); '
                 'static int worker(int x){__CPROVER_assert(x==0,"target");return x;} '
                 'int first(int x){return worker(x);}', encoding="utf-8")
    b.write_text('static int worker(int x){return x;} int second(int x){return worker(x);}', encoding="utf-8")
    harness.write_text('extern int first(int),second(int); void root(void){first(0);second(0);}', encoding="utf-8")
    task = Task(tmp_path / "task.json", (a,b,harness), "root", ("target",), timeout=45)
    report = discover(task, toolchain, tmp_path / "result")
    workers = [c for c in report.get("candidates", []) if c["name"] == "worker"]
    assert len(workers) == 1 and workers[0]["translation_unit"] == str(a), report


def test_real_synthesis_rejects_stale_discovery_identity(toolchain, tmp_path):
    task = Task.load(CASES / "scalar_target/task.json")
    sketch = replace(Sketch.load(CASES / "scalar_target/sketch.json"), max_rounds=1)
    report = synthesize(task, toolchain, sketch, tmp_path / "result", expected_dependencies="stale")
    assert report["synthesis_status"] == "UNKNOWN"
    assert "changed during synthesis" in report["reasons"][0]
    assert not report["nogoods"] and report["accepted_policies"] is None


def test_real_generator_receives_validation_feedback_then_retries(toolchain, tmp_path):
    task = Task.load(CASES / "scalar_target/task.json")
    generator = make_generator(tmp_path, '''
import json,sys
r=json.load(sys.stdin)
if r["attempt"]==0:
    print("invalid response")
else:
    assert "proposal_error" in r["feedback"][0]
    c=r["candidates"][0]
    sketch={"schema":1,"max_rounds":8,"solver_nodes":1000,"entries":[{
        "id":c["id"],"translation_unit":c["translation_unit"],"function":c["name"],
        "predicates":[c["predicates"][0]["expression"]],"returns":[-1]}]}
    print(json.dumps({"schema":1,"request_id":r["request_id"],"sketch":sketch}))
''', max_attempts=2, max_rounds=8)
    report = construct(task, toolchain, tmp_path / "result", generator=generator)
    assert report["construction_status"] == "SOLVED_FOR_HARNESS", report
    assert report["attempts"][0]["status"] == "INVALID_PROPOSAL"
    assert report["attempts"][1]["status"] == "SOLVED_FOR_HARNESS"


def test_real_generator_refines_a_semantically_infeasible_basis(toolchain, tmp_path):
    task = make_task(tmp_path, '''
extern _Bool nondet_bool(void);
int process_flag(_Bool flag) { __CPROVER_assert(!flag,"target"); return 0; }
void root(void) { _Bool flag=nondet_bool(); int rc=process_flag(flag);
    __CPROVER_assert(flag || rc==0,"contract.normal"); }
''')
    generator = make_generator(tmp_path, '''
import json,sys
r=json.load(sys.stdin)
c=r["candidates"][0]
predicates=[]
if r["attempt"]:
    assert r["feedback"][0]["synthesis_status"]=="INFEASIBLE_FOR_SKETCH"
    assert r["feedback"][0]["counterexamples"]
    predicates=[c["predicates"][0]["expression"]]
sketch={"schema":1,"max_rounds":8,"solver_nodes":1000,"entries":[{
    "id":c["id"],"translation_unit":c["translation_unit"],"function":c["name"],
    "predicates":predicates,"returns":[-1]}]}
print(json.dumps({"schema":1,"request_id":r["request_id"],"sketch":sketch}))
''', max_attempts=2, max_rounds=8)
    report = construct(task, toolchain, tmp_path / "result", generator=generator)
    assert report["construction_status"] == "SOLVED_FOR_HARNESS", report
    assert [r["status"] for r in report["attempts"]] == ["INFEASIBLE_FOR_SKETCH", "SOLVED_FOR_HARNESS"]


def test_real_generator_cannot_gate_harness_or_reuse_changed_program_evidence(toolchain, tmp_path):
    task = make_task(tmp_path, 'int action(int n){__CPROVER_assert(n==0,"target");return 0;} '
                     'void root(void){action(0);}')
    generator = make_generator(tmp_path, '''
import json,sys
from pathlib import Path
r=json.load(sys.stdin); c=r["candidates"][0]
if r["attempt"]:
    assert "outside" in r["feedback"][0]["proposal_error"]
    p=Path(c["translation_unit"])
    p.write_text(p.read_text(encoding="utf-8")+"\\nint added_state;\\n",encoding="utf-8")
sketch={"schema":1,"max_rounds":1,"solver_nodes":100,"entries":[{
    "id":c["id"],"translation_unit":c["translation_unit"],"function":c["name"] if r["attempt"] else "root",
    "predicates":[],"returns":[-1] if r["attempt"] else [None]}]}
print(json.dumps({"schema":1,"request_id":r["request_id"],"sketch":sketch}))
''', max_attempts=2, max_rounds=1)
    report = construct(task, toolchain, tmp_path / "result", generator=generator)
    assert report["construction_status"] == "UNKNOWN" and report["accepted_policies"] is None, report
    assert report["attempts"][0]["status"] == "INVALID_PROPOSAL"
    assert "changed during synthesis" in report["reasons"][0]
