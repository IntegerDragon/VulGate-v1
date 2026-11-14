"""C storage/return conversions and their consequences for rejection paths."""
import json
import shutil
import subprocess

import pytest

from tools.frontier import analyze_sources
from tools.frontier.__main__ import main
from tools.frontier.ctypes import INT, CType, parameters, type_context
from tools.frontier.returnflow import CallPlan, analyze_return_flow, integer
from tools.policy.actions import bind_actions


def flow(body, *, definitions="", model="lp64", return_type=None):
    return analyze_return_flow(body, body.index("target"), integer(-1, True),
                               types=type_context((("fixture.c", definitions),)),
                               integer_model=model, return_type=return_type)


# The injected call always returns -1. Each independent fixture below has
# completely defined C behavior on the explicitly checked native data model.
CASES = [
    ("", "int r=target(); unsigned char n=256; if(!n) r=0; return r;", 0),
    ("", "int r=target(); unsigned char n=1; if((n=256)==0) r=0; return r;", 0),
    ("", "int r=target(); unsigned char n=255; if(++n==0) r=0; return r;", 0),
    ("", "int r=target(); _Bool n=256; if(n) r=0; return r;", 0),
    ("", "int r=target(); if(r<1U) return r; return 0;", 0),
    ("", "int r=target(); unsigned char n=1; if(r<n) return r; return 0;", -1),
    ("", "int r=target(); if((unsigned char)256==0) r=0; return r;", 0),
    ("", "int r=target(); if((1 ? r : 0U)<1U) return r; return 0;", 0),
    ("", "int r=target(); unsigned n=0; if(n-1>1) r=0; return r;", 0),
    ("union U {int n; int other;};", "union U b={0}; int r=target(); b.other=1; if(b.n) r=0; return r;", 0),
    ("struct S {union {int n; int other;};};", "struct S b={0}; int r=target(); b.other=1; if(b.n) r=0; return r;", 0),
    ("struct S {union {int n; int other;} u;};", "struct S b={0}; int r=target(); b.u.other=1; if(b.u.n) r=0; return r;", 0),
    ("struct S {int n; int other;};", "struct S b={0}; int r=target(); b.other=1; if(b.n) r=0; return r;", -1),
]


@pytest.mark.parametrize("definitions,body,expected", CASES)
def test_integer_and_union_semantics(definitions, body, expected):
    result = flow(body, definitions=definitions)
    assert not result.reasons, result.evidence()
    assert {o.value.atom for o in result.outcomes} == {expected}


def test_types_against_native_c(tmp_path):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        pytest.skip("The type oracle requires a native C compiler")
    # Rename same-tag independent declarations to keep every C fixture valid.
    source = "#include <stdio.h>\n#include <limits.h>\nint target(void) {return -1;}\n"
    for i, (definition, body, _) in enumerate(CASES):
        source += definition.replace("struct S", f"struct S{i}") + "\n"
        source += f"int fixture{i}(void) {{{body.replace('struct S', f'struct S{i}')}}}\n"
    source += 'int main(void) { if(CHAR_BIT!=8 || sizeof(short)!=2 || sizeof(int)!=4 || sizeof(long long)!=8) return 77;\n'
    source += "\n".join(f'printf("%d\\n",fixture{i}());' for i in range(len(CASES)))
    source += "return 0;}\n"
    path, executable = tmp_path / "oracle.c", tmp_path / "oracle"
    path.write_text(source, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-O0", str(path), "-o", str(executable)], check=True, capture_output=True)
    run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
    if run.returncode == 77:
        pytest.skip("Native integer widths are outside this fixture's explicit model")
    assert run.returncode == 0, run.stderr
    assert list(map(int, run.stdout.splitlines())) == [expected for _, _, expected in CASES]


@pytest.mark.parametrize("definition,body,reason", [
    ("", "int r=target(); unsigned char n=256; if(!n) r=0; return r;", "integer_width_unbound"),
    ("", "int r=target(); char n=-1; if(n<0) return r; return 0;", "plain_char_signedness_unbound"),
    ("union U {int n; unsigned char bytes;};", "union U b={0}; int r=target(); b.bytes=1; if(b.n) r=0; return r;", "inactive_or_overlapping_union_member"),
    ("struct S {unsigned n:1;};", "struct S b={0}; int r=target(); b.n=2; if(!b.n) r=0; return r;", "unmodeled_declared_type:qualified_or_bitfield_type"),
    ("struct S {\n#if OPTION\nint n;\n#else\nlong n;\n#endif\n};", "struct S b={0}; int r=target(); if(b.n) r=0; return r;", "record_layout_incomplete"),
])
def test_missing_layout_and_integer_assumptions_remain_unknown(definition, body, reason):
    result = flow(body, definitions=definition, model="portable")
    assert result.status == "unknown", result.evidence()
    assert reason in result.reasons


def test_typedef_scope_before_and_after_shadowing():
    result = flow("T n=256; int r=target(); {T earlier=256; typedef unsigned char T; T later=256; if(earlier==256 && later==0) r=0;} return r;",
                  definitions="typedef int T;")
    assert not result.reasons, result.evidence()
    assert {o.value.atom for o in result.outcomes} == {0}


def test_missing_parameter_type_retains_its_local_identity():
    result = analyze_return_flow("int r=target(); if(n) r=0; return r;", 6, integer(-1, True),
                                 parameters="missing_t n")
    assert {o.value.atom for o in result.outcomes} == {-1, 0}
    assert all("n@parameter" in o.state.env and "n" not in o.state.env for o in result.outcomes)
    assert parameters("int **p", type_context(()))[0][1] == CType("pointer", target=CType("pointer", target=INT))


def test_forward_record_typedef_is_completed_by_its_definition():
    result = flow("S b={0}; int r=target(); b.n=256; if(!b.n) r=0; return r;",
                  definitions="typedef unsigned char uint8_t; typedef struct S S; struct S {uint8_t n;};")
    assert not result.reasons, result.evidence()
    assert {o.value.atom for o in result.outcomes} == {0}


def test_incompatible_pointer_cast_is_not_certified():
    result = flow("struct A a={0}; struct B *b=(struct B *)&a; int r=target(); b->n=1; return r;",
                  definitions="struct A {int n;}; struct B {int n;};")
    assert result.status == "unknown"
    assert "pointer_pointee_type_unbound_or_incompatible" in result.reasons


def test_target_and_wrapper_return_conversions(tmp_path):
    source = tmp_path / "return.c"
    for target_type, wrapper_type in [("unsigned char", "int"), ("int", "unsigned char")]:
        source.write_text(f"{target_type} target(void) {{return -1;}}\n"
                          f"{wrapper_type} wrapper(void) {{return target();}}\n"
                          "int caller(void) {int r=wrapper(); if(r<0) return r; return 0;}\n", encoding="utf-8")
        result = analyze_sources([source], "target", integer_model="lp64")
        assert not any(c["function"] == "target" and c["caller_contract"] == "confirmed_in_model" for c in result["candidates"])
    result = flow("return target();", return_type=CType("integer", "unsigned char"))
    assert {o.value.atom for o in result.outcomes} == {255}


def test_composed_parameter_and_return_types():
    context = type_context(())
    inner = "int r=target(); return r;"
    plan = CallPlan("wrapper", inner, "unsigned char n", inner.index("target"), integer(-1, True),
                    type_context=context, return_type=CType("integer", "unsigned char"))
    body = "int r=wrapper(256); if(r<0) return r; return 0;"
    result = analyze_return_flow(body, body.index("wrapper"), integer(-1, True), call_plan=plan, integer_model="lp64")
    assert not result.reasons, result.evidence()
    assert {o.value.atom for o in result.outcomes} == {0}


def test_later_file_typedef_does_not_retroactively_change_a_function():
    context = type_context((("fixture.c", "int earlier(void) {return 0;} typedef unsigned char T; int later(void) {return 0;}"),))
    bindings = dict(context.function_bindings)
    assert dict(bindings["earlier"])["T"].kind == "unknown"
    assert dict(bindings["later"])["T"] == CType("integer", "unsigned char")


def test_cli_and_binding_use_the_same_explicit_integer_model(tmp_path, capsys):
    source = tmp_path / "source.c"
    source.write_text("int target(void) {return -1;} int caller(void) {int r=target(); if(r<0) return r; return 0;}", encoding="utf-8")
    assert main(["--func", "target", "--src", str(source), "--integer-model", "lp64", "--json"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    candidate = catalog["candidates"][0]
    portable = analyze_sources([source], "target")["candidates"][0]
    assert candidate["candidate_id"] != portable["candidate_id"]
    metadata = {"target_function": "target", "protection_boundary": "function_entry",
                **{name: {"candidate_id": candidate["candidate_id"], "value": -1}
                   for name in ("unsafe_action", "unknown_action", "error_action")}}
    binding, errors = bind_actions(metadata, catalog)
    assert not errors
    assert binding["integer_model"] == "lp64"
    assert not binding["integer_model_verified_against_build"] and not binding["authorized"]
    catalog["analysis"]["integer_model"] = "portable"
    assert bind_actions(metadata, catalog)[1]


def test_action_binding_compares_converted_c_return_value(tmp_path):
    source = tmp_path / "bool.c"
    source.write_text("_Bool target(void) {return -1;} int caller(void) {if(target()) return -2; return 0;}", encoding="utf-8")
    catalog = analyze_sources([source], "target")
    candidate = catalog["candidates"][0]
    assert candidate["return_semantics"]["converted_integer"] == 1
    metadata = {"target_function": "target", "protection_boundary": "function_entry",
                "unsafe_action": {"candidate_id": candidate["candidate_id"], "value": -1}}
    assert bind_actions(metadata, catalog)[1]
    metadata["unsafe_action"]["value"] = 1
    assert not bind_actions(metadata, catalog)[1]
