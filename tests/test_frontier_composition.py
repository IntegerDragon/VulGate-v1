"""Composed rejection paths: returned value and memory travel together."""
import shutil
import subprocess

import pytest

from tools.frontier import analyze_sources
from tools.frontier.parse import parse_functions
from tools.frontier.returnflow import CallPlan, analyze_return_flow, integer
from tools.frontier.ctypes import type_context


TYPES = type_context((("fixture.c", "struct out {int n; int other;};"),))


def plan(body, parameters="struct out *o", *, nested=None, selected="target", source="fixture.c"):
    return CallPlan("fixture::wrapper", body, parameters, body.index(selected), integer(-1, True),
                    nested=nested, source_file=source, type_context=TYPES)


def run(body, call_plan, **kwargs):
    return analyze_return_flow(body, body.index("wrapper"), integer(-1, True),
                               call_plan=call_plan, source_file="fixture.c", types=TYPES, **kwargs)


OUTER = "struct out b={0}; int r=wrapper(&b); if(b.n) r=0; return r;"
CASES = [
    ("struct out *o", "int r=target(); o->other=4; return r;", OUTER, {-1}),
    ("struct out *o", "int r=target(); o->n=1; return r;", OUTER, {0}),
    ("struct out *o", "o->n=1; int r=target(); o->other=4; return r;", OUTER, {0}),
    ("int flag, struct out *o", "int r=target(); if(flag) o->n=1; return r;",
     OUTER.replace("wrapper(&b)", "wrapper(flag, &b)"), {-1, 0}),
    ("struct out *o", "int r=target(); if(flag) {o->n=1; return 0;} o->n=0; return r;",
     "struct out b={0}; int r=wrapper(&b); if(r<0 && b.n) return 99; return r;", {-1, 0}),
    ("struct out *p, struct out *q", "p->n=1; int r=target(); q->n=0; return r;",
     OUTER.replace("wrapper(&b)", "wrapper(&b, &b)"), {-1}),
    ("struct out *p, struct out *q", "p->n=1; int r=target(); q->n=0; return r;",
     OUTER.replace("struct out b={0};", "struct out b={0}, c={0};").replace("wrapper(&b)", "wrapper(&b, &c)"), {0}),
    ("struct out *o", "struct out b={0}; b.n=1; int r=target(); return r;", OUTER, {-1}),
    ("struct out *o", "o=0; int r=target(); return r;",
     "struct out b={0}; struct out *p=&b; int r=wrapper(p); if(p==0) r=0; return r;", {-1}),
    ("struct out *o", "shared=1; int r=target(); return r;",
     "struct out b={0}; shared=0; int r=wrapper(&b); if(shared) r=0; return r;", {0}),
    ("struct out *o", "if(flag) o->other=1; int r=target(); return r;",
     "struct out b={0}; int x=0; int r=(++x, wrapper(&b)); if(x!=1) r=0; return r;", {-1}),
]


@pytest.mark.parametrize("parameters,inner,outer,expected", CASES)
def test_composed_memory_and_return_paths(parameters, inner, outer, expected):
    result = run(outer, plan(inner, parameters))
    assert not result.reasons, result.evidence()
    assert {out.value.atom for out in result.outcomes} == expected
    assert result.composition == ("fixture::wrapper",)


def test_composed_paths_against_compiled_c(tmp_path):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        pytest.skip("The C oracle requires a native C compiler")
    source = "#include <stdio.h>\nstruct out {int n; int other;}; int flag,shared; int target(void) {return -1;}\n"
    for index, (parameters, inner, outer, _) in enumerate(CASES):
        source += f"int wrapper_{index}({parameters}) {{{inner}}}\n"
        source += f"int fixture_{index}(void) {{{outer.replace('wrapper(', f'wrapper_{index}(')}}}\n"
    source += "int main(void) {for(flag=0;flag<2;flag++) {\n"
    source += "\n".join(f'printf("{i} %d\\n", fixture_{i}());' for i in range(len(CASES)))
    source += "} return 0;}\n"
    path, executable = tmp_path / "oracle.c", tmp_path / "oracle"
    path.write_text(source, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-O0", str(path), "-o", str(executable)], check=True, capture_output=True)
    result = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=5)
    observed = {i: set() for i in range(len(CASES))}
    for line in result.stdout.splitlines():
        index, value = map(int, line.split())
        observed[index].add(value)
    for index, (parameters, inner, outer, expected) in enumerate(CASES):
        assert observed[index] == expected
        assert observed[index] == {o.value.atom for o in run(outer, plan(inner, parameters)).outcomes}


def test_multiple_wrapper_frames_compose_without_aliasing_local_names():
    leaf = plan("int r=target(); o->n=1; return r;")
    middle = plan("int r=leaf(o); o->other=7; return r;", nested=leaf, selected="leaf")
    result = run(OUTER, middle)
    assert result.status == "ignored", result.evidence()
    assert {o.value.atom for o in result.outcomes} == {0}


@pytest.mark.parametrize("inner,parameters,outer,reason", [
    ("static int n=0; int r=target(); if(n++) o->n=1; return r;", "struct out *o", OUTER,
     "unmodeled_storage_duration_or_linkage"),
    ("int local; *p=&local; return target();", "int **p", "int *p=0; int r=wrapper(&p); return r;",
     "composed_local_address_escaped"),
    ("return target();", "int o[]", OUTER, "composed_call_signature_or_depth_unmodeled"),
    ("int r=target(); o->n=1; return r;", "struct out *o",
     "struct out b={0}; return wrapper(&b)+b.n;", "unsequenced_composed_call_expression"),
])
def test_missing_semantics_cannot_certify_composition(inner, parameters, outer, reason):
    result = run(outer, plan(inner, parameters))
    assert result.status == "unknown", result.evidence()
    assert reason in result.reasons


def test_unknown_helper_still_invalidates_containing_object():
    result = run(OUTER, plan("int r=target(); change(&o->other); return r;"))
    assert result.status in {"unknown", "ignored"}
    assert {o.value.atom for o in result.outcomes} == {-1, 0}


def test_cross_file_globals_do_not_gain_a_linkage_identity_by_spelling():
    result = run("struct out b={0}; shared=1; int r=wrapper(&b); if(shared) r=0; return r;",
                 plan("shared=0; return target();", source="other.c"))
    assert result.status == "unknown"
    assert "unresolved_composed_global_identity" in result.reasons


def test_composition_shares_the_whole_query_budget():
    result = run(OUTER, plan("int i=0; while(i<100) i++; return target();"), max_states=12)
    assert result.status == "unknown"
    assert result.explored_states <= 12
    assert "state_budget_exhausted" in result.reasons


def test_inner_rejection_still_evaluates_argument_side_effects_in_c_order():
    result = run(OUTER, plan("int n=0; int r=target(n++, n); return r;"))
    assert result.status == "unknown"
    assert "unsequenced_composed_call_arguments" in result.reasons


def test_parameter_binding_uses_the_selected_conditional_definition():
    source = """#if MODE
int wrapper(int flag, struct out *o) {return target();}
#else
int wrapper(struct out *o, int flag) {return target();}
#endif
"""
    function = parse_functions(source, "fixture.c")["fixture.c::wrapper"]
    assert function.flow_parameters(function.body.index("target")) == "int flag, struct out *o"
    assert function.flow_parameters(function.body.rindex("target")) == "struct out *o, int flag"


@pytest.mark.parametrize("field,confirmed", [("other", True), ("n", False)])
def test_discovery_composes_the_actual_wrapper_effect(tmp_path, field, confirmed):
    path = tmp_path / "source.c"
    path.write_text(f"""
struct out {{int n; int other;}};
int target(void) {{return -1;}}
int wrapper(struct out *o) {{int r=target(); o->{field}=1; return r;}}
int caller(void) {{struct out o={{0}}; int r=wrapper(&o); if(o.n) r=0; if(r<0) return r; return 0;}}
""", encoding="utf-8")
    result = analyze_sources([path], "target")
    candidates = [c for c in result["candidates"] if c["function"] == "target"]
    assert any(c["caller_contract"] == "confirmed_in_model" for c in candidates) is confirmed
    if confirmed:
        continuation = candidates[0]["caller_evidence"][0]["return_flow"]["continuation_evidence"]
        assert continuation[0]["return_flow"]["composed_functions"] == [str(path) + "::wrapper"]
