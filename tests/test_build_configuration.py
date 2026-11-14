from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tools.verification.build import command_arguments, load_units, parse_unit, response_arguments, windows_arguments
from tools.verification.backend import CBMC
from tools.verification.engine import analyze, prepare_variant
from tools.verification.source import sha256
from tools.verification.spec import Policy, SpecificationError, Task
from tools.verification.toolchain import Toolchain


def make_task(directory, source='extern void __CPROVER_assert(_Bool,const char*); void root(void) { __CPROVER_assert(1,"target"); }'):
    file = directory / "program.c"
    file.write_text(source, encoding="utf-8")
    return Task(directory / "task.json", (file,), "root", ("target",), timeout=45)


@pytest.fixture
def toolchain():
    config = os.environ.get("VULGATE_TOOLCHAIN")
    if not config:
        pytest.skip("set VULGATE_TOOLCHAIN for build configuration integration tests")
    return Toolchain.load(config)


def test_real_backend_preserves_literal_argv(toolchain):
    values = [r'back\slash', 'two words', 'literal"quotes', r'%P\0%l\0']
    result = toolchain.run_external('python3', ['-c',
        'import json,sys; print(json.dumps(sys.argv[1:]))', *values])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == values


def test_compilation_command_quoting():
    assert command_arguments('gcc -DNAME=\'"a b"\' -c "source file.c"', "posix") == [
        "gcc", '-DNAME="a b"', "-c", "source file.c"]
    assert windows_arguments('"C:\\Program Files\\gcc.exe" -I"include dir" -c "source file.c"') == [
        "C:\\Program Files\\gcc.exe", "-Iinclude dir", "-c", "source file.c"]
    with pytest.raises(SpecificationError):
        command_arguments("gcc -c a.c && echo done", "posix")
    with pytest.raises(SpecificationError):
        command_arguments("gcc $CFLAGS -c a.c", "posix")


def test_flag_order_and_frontend_last_option_semantics(tmp_path):
    task = make_task(tmp_path)
    unit = parse_unit(task.sources[0], tmp_path, ["gcc", "-DVALUE=1", "-UVALUE", "-DVALUE=2", "-m64", "-m32",
                      "-funsigned-char", "-fsigned-char", "-std=c99", "-std=c11", "-MMD", "-MF", "dep.d",
                      "-c", "program.c", "-o", "program.o"], {})
    assert unit.preprocess_flags[:3] == ("-DVALUE=1", "-UVALUE", "-DVALUE=2")
    assert unit.frontend_flags == ("-m32", "-fsigned-char", "-std=c11")
    assert unit.provenance["discarded_build_outputs"] == ["-MMD", "-MF", "dep.d", "-c", "-o", "program.o"]


@pytest.mark.parametrize("flag", ["-fwrapv", "-ffast-math", "-Ofast", "-fpack-struct", "-fplugin=custom.so", "-Wp,-P"])
def test_unqualified_semantic_flags_are_not_silently_dropped(tmp_path, flag):
    task = make_task(tmp_path)
    with pytest.raises(SpecificationError):
        parse_unit(task.sources[0], tmp_path, ["gcc", flag, "-c", "program.c"], {})


def test_response_dependencies_and_cycles(tmp_path):
    task = make_task(tmp_path)
    inner = tmp_path / "inner.rsp"
    outer = tmp_path / "outer.rsp"
    inner.write_text('-DVALUE=3 -I"include dir"', encoding="utf-8")
    outer.write_text("@inner.rsp -std=c11 -c program.c", encoding="utf-8")
    before = parse_unit(task.sources[0], tmp_path, ["gcc", "@outer.rsp"], {})
    assert before.preprocess_flags[:2] == ("-DVALUE=3", "-Iinclude dir")
    inner.write_text('-DVALUE=4 -I"include dir"', encoding="utf-8")
    after = parse_unit(task.sources[0], tmp_path, ["gcc", "@outer.rsp"], {})
    assert before.provenance["response_files"] != after.provenance["response_files"]
    inner.write_text("@outer.rsp", encoding="utf-8")
    with pytest.raises(SpecificationError, match="cyclic"):
        parse_unit(task.sources[0], tmp_path, ["gcc", "@outer.rsp"], {})


def test_gnu_response_escaping_differs_from_shell_single_quotes():
    assert response_arguments(r"-I'include\ dir' -DNAME=\"a\ b\" ''") == ["-Iinclude dir", '-DNAME="a b"', ""]
    for invalid in ("unterminated\\", "'unterminated", "-DNAME=a\0b"):
        with pytest.raises(SpecificationError):
            response_arguments(invalid)


def test_database_selection_requires_an_unambiguous_command(tmp_path):
    task = make_task(tmp_path)
    database = tmp_path / "compile_commands.json"
    records = [{"directory": str(tmp_path), "file": "program.c", "output": f"program-{n}.o",
                "arguments": ["gcc", f"-DVALUE={n}", "-c", "program.c"]} for n in (1, 2)]
    database.write_text(json.dumps(records), encoding="utf-8")
    task = replace(task, compilation_database=database)
    with pytest.raises(SpecificationError, match="ambiguous"):
        load_units(task)
    selected = load_units(replace(task, units=({"source": "program.c", "output": "program-2.o"},)))
    assert selected[0].preprocess_flags == ("-DVALUE=2",)
    assert selected[0].provenance["record_index"] == 1


def test_database_does_not_guess_harness_options(tmp_path):
    task = make_task(tmp_path)
    database = tmp_path / "compile_commands.json"
    database.write_text("[]", encoding="utf-8")
    task = replace(task, compilation_database=database)
    with pytest.raises(SpecificationError, match="provide explicit unit flags"):
        load_units(task)
    assert load_units(replace(task, units=({"source": "program.c", "flags": ["-std=c11"]},)))[0].frontend_flags == ("-std=c11",)


def test_changed_preprocessed_snapshot_is_rejected_before_compilation(tmp_path):
    task = make_task(tmp_path)
    original = task.sources[0].read_bytes()
    snapshot = tmp_path / "source.i"
    snapshot.write_bytes(original + b"\nint changed;\n")
    with pytest.raises(SpecificationError, match="snapshot changed"):
        prepare_variant(task, Toolchain(), [{"source": task.sources[0], "path": snapshot, "sha256": sha256(original)}],
                        [], tmp_path / "variant")


def test_task_loads_build_configuration(tmp_path):
    task = make_task(tmp_path)
    (tmp_path / "compile_commands.json").write_text("[]", encoding="utf-8")
    task.path.write_text(json.dumps({"schema": 1, "sources": ["program.c"], "entry": "root", "targets": ["target"],
                                    "compilation_database": "compile_commands.json", "command_syntax": "posix",
                                    "units": [{"source": "program.c", "flags": ["-std=c90"]}]}), encoding="utf-8")
    loaded = Task.load(task.path)
    assert loaded.compilation_database == tmp_path / "compile_commands.json"
    assert load_units(loaded)[0].frontend_flags == ("-std=c89",)
    with pytest.raises(SpecificationError, match="language selection after"):
        parse_unit(task.sources[0], tmp_path, ["gcc", "program.c", "-x", "c"], {})


@pytest.mark.parametrize("bits,unsigned", [(64, False), (64, True)])
def test_real_per_unit_abi_configuration(toolchain, tmp_path, bits, unsigned):
    task = make_task(tmp_path, '''
extern void __CPROVER_assert(_Bool,const char*);
void root(void) {
    __CPROVER_assert(sizeof(void*)==EXPECTED_POINTER,"target");
    __CPROVER_assert(((char)-1>0)==EXPECTED_UNSIGNED,"contract.char_sign");
}
''')
    flags = ["-std=c11", f"-m{bits}", "-funsigned-char" if unsigned else "-fsigned-char",
             f"-DEXPECTED_POINTER={bits // 8}", f"-DEXPECTED_UNSIGNED={int(unsigned)}"]
    task = replace(task, units=({"source": "program.c", "flags": flags},))
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["protected"]["target"] == "PROVED_FOR_HARNESS", report
    assert report["protected"]["contracts_and_runtime_checks"] == "PROVED_FOR_HARNESS"
    dependencies = json.loads((tmp_path / "result/dependencies.json").read_text(encoding="utf-8"))
    abi = dependencies["preprocessed"][0]["build"]["abi"]
    assert abi["pointer_size"] == bits // 8 and abi["char_is_unsigned"] == int(unsigned)


def test_real_response_escaping_language_and_macro_undef_follow_native_driver(toolchain, tmp_path):
    include = tmp_path / "include dir"
    include.mkdir()
    (include / "fixture.h").write_text("#define EXPECTED 11\n", encoding="utf-8")
    source = tmp_path / "source.data"
    source.write_text('#include "fixture.h"\n#ifdef VALUE\n#error VALUE must be undefined\n#endif\n'
                      'int value(void) { return EXPECTED; }\n', encoding="utf-8")
    response = tmp_path / "flags.rsp"
    response.write_text(r"-I'include\ dir' -DVALUE=7 -UVALUE -x c -std=c11 -c source.data", encoding="utf-8")
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([{"directory": toolchain.path(tmp_path), "file": "source.data",
                                     "arguments": ["gcc", "@flags.rsp"]}]), encoding="utf-8")
    task = Task(tmp_path / "task.json", (source,), "value", ("target",), compilation_database=database)
    snapshot = CBMC(toolchain, task, tmp_path / "result").preprocess()[0]
    native = toolchain.run_external("gcc", ["@flags.rsp", "-E"], cwd=tmp_path)
    assert native.returncode == 0, native.stderr
    assert snapshot["path"].read_bytes() == native.stdout.encode("utf-8")
    assert "return 11" in native.stdout


def test_real_i386_layout_disagreement_is_not_silently_accepted(toolchain, tmp_path):
    # CBMC 6.11.0 currently gives i386 long double a 12-byte natural alignment,
    # disagreeing with GCC. Keep this qualification gap visible, not suppressed.
    task = make_task(tmp_path)
    task = replace(task, units=({"source": "program.c", "flags": ["-std=c11", "-m32"]},))
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["status"] == "UNKNOWN"
    assert "ABI qualification failed" in report["reasons"][0]
    assert "long_double_alignment" in report["reasons"][0]


def test_real_database_preserves_directory_flags_and_invalidates_cache(toolchain, tmp_path):
    source_dir = tmp_path / "src"
    include = tmp_path / "include dir"
    build = tmp_path / "build"
    for folder in (source_dir, include, build):
        folder.mkdir()
    (include / "limits.h").write_text("#define EXTRA 8\n", encoding="utf-8")
    source = source_dir / "operation.c"
    source.write_text('''
#include "limits.h"
extern void __CPROVER_assert(_Bool,const char*);
int operation(unsigned count) {
    const char *origin=__FILE__;
    __CPROVER_assert(origin[0]=='.' && EXTRA==8,"contract.build_context");
    __CPROVER_assert(count<=LIMIT,"target");
    return 0;
}
''', encoding="utf-8")
    harness = tmp_path / "harness.c"
    harness.write_text('''
extern void __CPROVER_assume(_Bool);
extern unsigned nondet_uint(void);
extern int operation(unsigned);
void root(void) { unsigned count=nondet_uint(); __CPROVER_assume(count<6); operation(count); }
''', encoding="utf-8")
    database = tmp_path / "compile_commands.json"
    record = {"directory": toolchain.path(build), "file": "../src/operation.c", "output": "operation.o",
              "arguments": ["gcc", "-std=c99", "-m64", "-I../include dir", "-DLIMIT=9", "-ULIMIT", "-DLIMIT=3",
                            "-O2", "-MMD", "-MF", "operation.d", "-c", "../src/operation.c", "-o", "operation.o"]}
    database.write_text(json.dumps([record]), encoding="utf-8")
    task = Task(tmp_path / "task.json", (source, harness), "root", ("target",), timeout=45,
                compilation_database=database, units=({"source": "harness.c", "flags": ["-std=c11", "-m64"]},))
    policy = Policy("gate", source, "operation", -1, {"op": ">", "args": [{"var": "count"}, {"const": 3}]})
    before = analyze(task, toolchain, [policy], tmp_path / "result")
    assert before.get("protected", {}).get("target") == "PROVED_FOR_HARNESS", before
    assert before["baseline"]["contracts_and_runtime_checks"] == "PROVED_FOR_HARNESS"
    assert not (build / "operation.d").exists() and not (build / "operation.o").exists()
    record["arguments"][6] = "-DLIMIT=2"
    database.write_text(json.dumps([record]), encoding="utf-8")
    after = analyze(task, toolchain, [policy], tmp_path / "result")
    assert after["protected"]["target"] == "REFUTED", after
    assert not after["actions"][0]["cache_hit"]
    assert before["dependencies_sha256"] != after["dependencies_sha256"]


def test_real_incompatible_units_are_rejected_before_linking(toolchain, tmp_path):
    task = make_task(tmp_path)
    extra = tmp_path / "extra.c"
    extra.write_text("int helper(void) { return 0; }", encoding="utf-8")
    task = replace(task, sources=(*task.sources, extra), units=(
        {"source": "program.c", "flags": ["-fsigned-char"]},
        {"source": "extra.c", "flags": ["-funsigned-char"]}))
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report["status"] == "UNKNOWN"
    assert "incompatible ABI" in report["reasons"][0]


def test_real_static_symbols_remain_distinct_across_units(toolchain, tmp_path):
    first = tmp_path / "first.c"
    second = tmp_path / "second.c"
    harness = tmp_path / "harness.c"
    first.write_text('extern void __CPROVER_assert(_Bool,const char*); '
                     'static int compute(void) { __CPROVER_assert(1,"target"); return 1; } '
                     'int first(void) { return compute(); }', encoding="utf-8")
    second.write_text('static int compute(void) { return 2; } int second(void) { return compute(); }', encoding="utf-8")
    harness.write_text('extern int first(void),second(void); void root(void) { first(); second(); }', encoding="utf-8")
    sources = (first, second, harness)
    task = Task(tmp_path / "task.json", sources, "root", ("target",), timeout=45,
                units=tuple({"source": s.name, "flags": ["-std=c11"]} for s in sources))
    report = analyze(task, toolchain, [], tmp_path / "result")
    assert report.get("protected", {}).get("target") == "PROVED_FOR_HARNESS", report
    graph = json.loads((tmp_path / "result/candidates.json").read_text(encoding="utf-8"))
    names = [candidate["name"] for candidate in graph["candidates"]]
    assert names.count("compute") == 1 and "first" in names and "root" in names and "second" not in names
