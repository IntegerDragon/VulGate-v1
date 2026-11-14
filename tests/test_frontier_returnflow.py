"""Observable C semantics and conservative counterexamples for return-flow analysis."""
import shutil
import subprocess

import pytest

from tools.frontier.returnflow import Value, analyze_return_flow, candidate_value, integer
from tools.frontier.parse import parse_functions, source_views
from tools.frontier.syntax import parse_flow


def flow(body, expression="-1", kind="neg", **kwargs):
    return analyze_return_flow(body, body.index("target"), candidate_value(expression, kind), **kwargs)


def test_discovery_masks_literals_without_breaking_semantic_syntax():
    source = '''int caller(void) {
    const char *message = "假的 target(), likely(()), , \\"";
    int r = __builtin_expect(target(), 0);
    if (r < 0) return r;
    return 0;
}'''
    discovery, semantic = source_views(source)
    assert len(discovery) == len(semantic) == len(source)
    assert discovery.count("target") == 1
    assert '假的 target(), likely(())' in semantic
    assert '__builtin_expect' not in semantic
    function = parse_functions(source, "fixture.c")["fixture.c::caller"]
    body, offset, base = function.flow_body(function.body.index("target"))
    graph = parse_flow(body)
    assert not graph.body.has_error
    result = analyze_return_flow(body, offset, candidate_value("-1", "neg"))
    assert result.status == "checked", result.evidence()
    assert result.outcomes[0].state.trace[0] == function.body.index("target")


def test_erased_attribute_and_builtin_literals_are_not_restored():
    source = '''int __attribute__((section("target()"))) caller(void) {
    int r = target();
    if (__builtin_expect(r < 0, sizeof("hidden(),("))) return r;
    return 0;
}'''
    _, semantic = source_views(source)
    assert 'section' not in semantic and 'hidden' not in semantic
    assert semantic.count('target') == 1
    function = parse_functions(source, "fixture.c")["fixture.c::caller"]
    assert flow(function.semantic_body).status == "checked"


@pytest.mark.parametrize("directive,constants,expected", [
    ("#if 0", {}, {-1}),
    ("#if 1", {}, {0}),
    ("#if MODE", {"MODE": 0}, {-1}),
    ("#ifdef MODE", {"MODE": 0}, {0}),
    ("#ifndef MODE", {"MODE": 0}, {-1}),
])
def test_known_configuration_preserves_alternative_paths(directive, constants, expected):
    body = f"int r=target();\n{directive}\nr=0;\n#elif 1\nr=r;\n#else\nr=2;\n#endif\nreturn r;"
    result = flow(body, constants=constants)
    assert {o.value.atom for o in result.outcomes} == expected
    assert not result.reasons


def test_unknown_configuration_does_not_run_both_branches_sequentially():
    body = "int r=target();\n#if MODE\nr=0;\n#else\nr=r;\n#endif\nreturn r;"
    result = flow(body)
    assert result.status == "unknown"
    assert "unresolved_configuration" in result.reasons
    assert {o.value.atom for o in result.outcomes} == {-1, 0}


def test_conditional_function_definitions_keep_separate_flow_and_offsets():
    source = '''#if MODE
int caller(void) {int r=target(); return 0;}
#else
int caller(void) {const char *s="说明"; int r=target(); if(r<0) return r; return 0;}
#endif
'''
    function = parse_functions(source, "fixture.c")["fixture.c::caller"]
    offsets = [function.body.index("target"), function.body.rindex("target")]
    results = []
    for offset in offsets:
        body, local, base = function.flow_body(offset)
        assert local + base == offset
        assert body.count("target") == 1
        results.append(analyze_return_flow(body, local, candidate_value("-1", "neg")))
    assert [r.status for r in results] == ["ignored", "checked"]


# These finite programs also run in a real C compiler below. Both branches of
# flag are enumerated there; the interpreter receives an unknown flag.
FINITE = [
    ("int r=target(); return r;", "propagated", {-1}),
    ("int r=target(); if(r<0) return r; return 0;", "checked", {-1}),
    ("int r=target(); if(r<0) {} return 0;", "ignored", {0}),
    ("int r=target(); if(r<0) {if(flag) return r;} return 0;", "ignored", {-1, 0}),
    ("int r=target(); if(flag) {} else {} return r;", "propagated", {-1}),
    ("int r=target(); if(flag) r=0; return r;", "ignored", {-1, 0}),
    ("int r=target(); {int r=0; if(r) return 3;} return r;", "propagated", {-1}),
    ("int r=target(); {int r=0; r=2;} r=0; return r;", "ignored", {0}),
    ("int r=target(); if(r<0) goto fail; return 0; fail: return r;", "checked", {-1}),
    ("int r=target(); if(r<0) goto done; r=4; done: return 0;", "ignored", {0}),
    ("int r=target(); switch(r) {case -2: case -1: return -4; default: return 0;}", "checked", {-4}),
    ("int r=target(); switch(r) {case -1: r=-3; case -2: r+=1; break; default:r=0;} return r;", "ignored", {-2}),
    ("int r=target(); for(int i=0;i<3;i++) { if(i==1) continue; } return r;", "propagated", {-1}),
    ("int r=target(); int i=0; do {i++; if(i==2) break;} while(i<3); return r;", "propagated", {-1}),
    ("int r=target(); while(0) r=0; return r;", "propagated", {-1}),
    ("int r=target(); return !r;", "transformed", {0}),
    ("struct out {int n;}; struct out b={0}; int r=target(&b); if(b.n) r=b.n; return r;", "propagated", {-1}),
    ("struct out {int n;int m;}; struct out b={.m=4}; int r=target(&b); if(b.n) r=b.n; return r;", "propagated", {-1}),
    ("int r=target(); if(0 && (r=0)) return 2; return r;", "propagated", {-1}),
    ("int r=target(); if(1 || (r=0)) {} return r;", "propagated", {-1}),
]


@pytest.mark.parametrize("body,status,expected", FINITE)
def test_finite_return_paths(body, status, expected):
    result = flow(body)
    assert result.status == status, result.evidence()
    assert {o.value.atom for o in result.outcomes} == expected


def test_finite_paths_against_compiled_c(tmp_path):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        pytest.skip("The differential C oracle requires a native C compiler")
    source = "#include <stdio.h>\nint flag; int target() { return -1; }\n"
    source += "\n".join(f"int fixture_{i}(void) {{{body}}}" for i, (body, _, _) in enumerate(FINITE))
    source += "\nint main(void) {for(flag=0;flag<2;flag++){\n"
    source += "\n".join(f'printf("{i} %d\\n", fixture_{i}());' for i in range(len(FINITE)))
    source += "\n} return 0;}\n"
    path = tmp_path / "oracle.c"
    executable = tmp_path / "oracle"
    path.write_text(source, encoding="utf-8")
    subprocess.run([compiler, "-std=c11", "-O0", str(path), "-o", str(executable)],
                   check=True, capture_output=True, text=True)
    observed = {i: set() for i in range(len(FINITE))}
    run = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=5)
    for line in run.stdout.splitlines():
        index, value = map(int, line.split())
        observed[index].add(value)
    for i, (body, _, expected) in enumerate(FINITE):
        assert observed[i] == expected
        assert observed[i] == {o.value.atom for o in flow(body).outcomes}


@pytest.mark.parametrize("body,expression,kind,reason", [
    ("int *p=target(); return *p;", "NULL", "null", "invalid_pointer_dereference"),
    ("int *p=target(); int v=*p; if(!p) return -1; return v;", "NULL", "null", "invalid_pointer_dereference"),
    ("struct obj *p=target(); return p->n;", "ERR_PTR(-EINVAL)", "err_ptr", "invalid_pointer_dereference"),
    ("int a[4]; int r=target(); return a[r];", "-1", "neg", "negative_error_used_as_index"),
    ("int *p=target(); if(p==0 && flag) return -1; return *p;", "NULL", "null", "invalid_pointer_dereference"),
])
def test_unsafe_use_is_a_veto(body, expression, kind, reason):
    result = flow(body, expression, kind)
    assert result.status == "unsafe", result.evidence()
    assert reason in result.reasons


@pytest.mark.parametrize("body,expression,kind", [
    ("int *p=target(); if(!p) return -1; return *p;", "NULL", "null"),
    ("struct obj *p=target(); if(IS_ERR(p)) return -1; return p->n;", "ERR_PTR(-EINVAL)", "err_ptr"),
])
def test_pointer_check_prevents_bad_access(body, expression, kind):
    assert flow(body, expression, kind).status == "checked"


@pytest.mark.parametrize("body,reason", [
    ("int r=target(); for(;;) {}", "nonterminating_path"),
    ("int r=target(); while(flag) {} return r;", "nonterminating_path"),
    ("int r=target(); if(flag && (r=0)) {} return r;", "conditional_short_circuit_effects"),
    ("int r=target(); return (unsigned)r;", "integer_width_unbound"),
    ("unsigned r=target(); if(r<0) return -1; return 0;", "integer_width_unbound"),
    ("int r=target(); consume(r); return r;", "injected_value_passed_to_unmodeled_call"),
])
def test_unmodeled_semantics_cannot_confirm(body, reason):
    result = flow(body)
    assert result.status == "unknown", result.evidence()
    assert reason in result.reasons


def test_budget_before_selected_call_is_still_unknown():
    result = flow("int i=0; while(i<100) i++; int r=target(); return r;", max_states=8)
    assert result.status == "unknown"
    assert "state_budget_exhausted" in result.reasons


def test_macro_aliases_are_not_assumed_distinct():
    result = flow("int r=target(); if(r==-EWOULDBLOCK) return 0; return r;", "-EAGAIN")
    assert {o.value.atom for o in result.outcomes} == {"-EAGAIN", 0}
    assert result.status == "ignored"


def test_unknown_call_invalidates_aliased_field():
    result = flow("struct out {int n;}; struct out b={0}; struct out *p=&b; int r=target(); change(p); if(b.n) return 0; return r;")
    assert result.status == "ignored"


@pytest.mark.parametrize("setup,call,condition", [
    ("struct out {int member; int result;}; struct out b={0};", "change(&b.member)", "b.result"),
    ("struct out {int *ptr;}; int n=0; struct out b={.ptr=&n};", "change(&b)", "n"),
    ("shared=0;", "change()", "shared"),
])
def test_unknown_effects_do_not_preserve_siblings_reachable_objects_or_globals(setup, call, condition):
    # Each unmodeled helper can legally overwrite the tested location in C.
    # It may discard the injected error, even without receiving that value.
    result = flow(f"{setup} int r=target(); {call}; if({condition}) r=0; return r;")
    assert result.status in {"ignored", "unknown"}, result.evidence()
    assert {o.value.atom for o in result.outcomes} == {-1, 0}
    assert {o.value.atom for o in result.outcomes} == {0, -1}


def test_escaped_local_cannot_retain_value_across_unknown_call():
    result = flow("int r=0; remember(&r); r=target(); change(); return r;")
    assert result.status == "unknown"
    assert {o.value.atom for o in result.outcomes} == {None}


def test_zero_default_not_reused_after_aggregate_assignment():
    result = flow("struct out {int n;}; struct out b={0}; int r=target(); b=other; if(b.n) return 0; return r;")
    assert result.status == "ignored"
    assert {o.value.atom for o in result.outcomes} == {0, -1}


def test_utf8_call_offset_uses_character_positions():
    assert flow("/* 中文 */ int r=target(); return r;").status == "propagated"


def test_propagation_cannot_skip_wrappers_output_writes():
    body = "struct out {int n;}; struct out b={0}; int r=target(&b); if(b.n) r=0; return r;"
    result = flow(body, entry_injection=False)
    assert result.status == "unknown"
    assert "propagated_callee_effects_unmodeled" in result.reasons


def test_propagation_without_pointer_arguments_still_has_global_effects():
    result = flow("shared=0; int r=target(); if(shared) r=0; return r;", entry_injection=False)
    assert result.status == "unknown"
    assert "propagated_callee_effects_unmodeled" in result.reasons
    assert {o.value.atom for o in result.outcomes} == {-1, 0}
