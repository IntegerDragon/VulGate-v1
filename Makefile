UNAME_S := $(shell uname -s)
CC ?= cc
PYTHON ?= python3
PYTEST ?= $(shell $(PYTHON) -m pytest --version >/dev/null 2>&1 && echo "$(PYTHON) -m pytest" || command -v pytest 2>/dev/null || echo "$(PYTHON) -m pytest")

BUILD_DIR := build
USER_BUILD := $(BUILD_DIR)/workloads/basic
COPYFAIL_BUILD := $(BUILD_DIR)/workloads/copyfail
RULEGEN_DIR := tools/rulegen
POLICY_DIR := tools/policy
USER_RUNTIME := runtime/user
POLICY_BUILD := $(BUILD_DIR)/policies
POC ?= poc
OUT ?= $(BUILD_DIR)/export
SHIELD_MODE ?= kernel

CFLAGS ?= -O2 -g
COMMON_CFLAGS := -std=c11 -Wall -Wextra -fPIC -Iruntime

ifeq ($(UNAME_S),Darwin)
SHARED_EXT := dylib
SHARED_FLAGS := -dynamiclib -Wl,-undefined,dynamic_lookup
APP_RPATH := -Wl,-rpath,@loader_path
DL_LIBS :=
RUN_ENV := AUTOSHIELD_RULE="$(CURDIR)/$(USER_BUILD)/shadow.bin" DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(CURDIR)/$(USER_BUILD)/libautoshield_preload.$(SHARED_EXT)"
COPYFAIL_RUN_ENV := AUTOSHIELD_RULE="$(CURDIR)/$(COPYFAIL_BUILD)/shadow.bin" DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES="$(CURDIR)/$(COPYFAIL_BUILD)/libautoshield_copyfail.$(SHARED_EXT)"
else
SHARED_EXT := so
SHARED_FLAGS := -shared
APP_RPATH := -Wl,-rpath,'$$ORIGIN'
DL_LIBS := -ldl
RUN_ENV := AUTOSHIELD_RULE="$(CURDIR)/$(USER_BUILD)/shadow.bin" LD_PRELOAD="$(CURDIR)/$(USER_BUILD)/libautoshield_preload.$(SHARED_EXT)"
COPYFAIL_RUN_ENV := AUTOSHIELD_RULE="$(CURDIR)/$(COPYFAIL_BUILD)/shadow.bin" LD_PRELOAD="$(CURDIR)/$(COPYFAIL_BUILD)/libautoshield_copyfail.$(SHARED_EXT)"
endif

.PHONY: all user offline kernel-module export export-kernel export-frida run poc copyfail copyfail-rule policy check test test-security test-robustness test-policy test-frontier test-perf clean safe-read-probe frontier

all: run

export: $(if $(filter kernel,$(SHIELD_MODE)),kernel-module,$(if $(filter frida,$(SHIELD_MODE)),frida))
	@case "$(SHIELD_MODE)" in kernel|frida) ;; \
	  *) echo "Unsupported SHIELD_MODE=$(SHIELD_MODE). Use kernel or frida."; exit 1 ;; \
	esac
	@bash tools/export_artifacts.sh "$(SHIELD_MODE)" "$(OUT)"

kernel-module:
	@bash tools/build_kernel_module.sh

export-kernel: kernel-module
	@bash tools/export_artifacts.sh kernel "$(OUT)"

export-frida: frida
	@bash tools/export_artifacts.sh frida "$(OUT)"

.PHONY: frida test-frida
frida:
	$(PYTHON) runtime/frida/build.py --with-fixture --cc "$(CC)"

test-frida:
	$(PYTHON) -m pytest tests/test_frida_backend.py -v


policy: $(POLICY_BUILD)/cve_2022_0778/verify_report.json $(POLICY_BUILD)/cve_2020_25212/verify_report.json
	@echo "== local policy bundles =="
	@$(PYTHON) -c "from pathlib import Path; import json; root=Path('$(POLICY_BUILD)'); print('\n'.join(str(p) for p in sorted(root.glob('*/*')) if p.is_file()))"

$(POLICY_BUILD)/cve_2022_0778/verify_report.json: $(POLICY_DIR)/compile_policy.py $(POLICY_DIR)/compiler.py $(POLICY_DIR)/candidate.py $(POLICY_DIR)/dsl.py $(POLICY_DIR)/ir.py tests/policies/cve_2022_0778/policy.md | $(POLICY_BUILD)/cve_2022_0778
	$(PYTHON) $(POLICY_DIR)/compile_policy.py tests/policies/cve_2022_0778/policy.md --output-dir $(POLICY_BUILD)/cve_2022_0778

$(POLICY_BUILD)/cve_2020_25212/verify_report.json: $(POLICY_DIR)/compile_policy.py $(POLICY_DIR)/compiler.py $(POLICY_DIR)/candidate.py $(POLICY_DIR)/dsl.py $(POLICY_DIR)/ir.py tests/policies/cve_2020_25212/policy.md | $(POLICY_BUILD)/cve_2020_25212
	$(PYTHON) $(POLICY_DIR)/compile_policy.py tests/policies/cve_2020_25212/policy.md --output-dir $(POLICY_BUILD)/cve_2020_25212

$(POLICY_BUILD)/cve_2022_0778 $(POLICY_BUILD)/cve_2020_25212:
	mkdir -p $@

offline: $(USER_BUILD)/shadow.bin

$(USER_BUILD)/shadow.bin: $(RULEGEN_DIR)/gen_rule.py $(RULEGEN_DIR)/template.c $(RULEGEN_DIR)/verifier.py $(RULEGEN_DIR)/ebpf_asm.py $(RULEGEN_DIR)/rules/user_oob.asm.in
	$(PYTHON) $(RULEGEN_DIR)/gen_rule.py --demo user_oob --max-len 16 --output-dir $(USER_BUILD) --verify

user: offline $(USER_BUILD)/libvuln.$(SHARED_EXT) $(USER_BUILD)/vuln_app $(USER_BUILD)/libautoshield_preload.$(SHARED_EXT)

run: poc

poc: user
	@echo "== generated shadow/eBPF artifacts =="
	@echo "review C:        $(USER_BUILD)/shadow.c"
	@echo "eBPF template:   $(RULEGEN_DIR)/rules/user_oob.asm.in"
	@echo "eBPF bytecode:   $(USER_BUILD)/shadow.bin"
	@echo "verify report:   $(USER_BUILD)/verify_report.json"
	@echo "== baseline: run without hook =="
	@set +e; \
	unprotected="$$( $(CURDIR)/$(USER_BUILD)/vuln_app $(POC) 2>&1 )"; \
	rc=$$?; \
	set -e; \
	echo "$$unprotected"; \
	echo "exit=$$rc"
	@echo
	@echo "== protected: run with hook + shadow eBPF =="
	@set +e; \
	protected="$$( $(RUN_ENV) $(CURDIR)/$(USER_BUILD)/vuln_app $(POC) 2>&1 )"; \
	rc=$$?; \
	set -e; \
	echo "$$protected"; \
	echo "exit=$$rc"

## copyfail workload – shows AutoShield blocking CVE-2026-31431 page-cache write.
## Rule: block patch_cache when splice len > 4 (ESN targeting /etc/passwd cache).
## Prints: AUTOSHIELD target=patch_cache decision=BLOCK len=60 insns=5 reads=0 helpers=1
copyfail: copyfail-rule $(COPYFAIL_BUILD)/libpatch_cache.$(SHARED_EXT) $(COPYFAIL_BUILD)/copyfail_app $(COPYFAIL_BUILD)/libautoshield_copyfail.$(SHARED_EXT)
	@echo "== shadow rule (copyfail: block if splice len > 4) =="
	@echo "review C:    $(COPYFAIL_BUILD)/shadow.c"
	@echo "eBPF binary: $(COPYFAIL_BUILD)/shadow.bin"
	@echo ""
	@echo "== baseline (no AutoShield): normal call =="
	@set +e; $(COPYFAIL_BUILD)/copyfail_app normal 2>&1; echo "exit=$$?"
	@echo ""
	@echo "== baseline (no AutoShield): poc call =="
	@set +e; $(COPYFAIL_BUILD)/copyfail_app poc 2>&1; echo "exit=$$?"
	@echo ""
	@echo "== protected (AutoShield): normal call → expect PASS =="
	@set +e; $(COPYFAIL_RUN_ENV) $(COPYFAIL_BUILD)/copyfail_app normal 2>&1; echo "exit=$$?"
	@echo ""
	@echo "== protected (AutoShield): poc call → expect BLOCK =="
	@set +e; $(COPYFAIL_RUN_ENV) $(COPYFAIL_BUILD)/copyfail_app poc 2>&1; echo "exit=$$?"

copyfail-rule: $(COPYFAIL_BUILD)/shadow.bin

$(COPYFAIL_BUILD)/shadow.bin: $(RULEGEN_DIR)/gen_rule.py $(RULEGEN_DIR)/template.c $(RULEGEN_DIR)/verifier.py $(RULEGEN_DIR)/ebpf_asm.py $(RULEGEN_DIR)/rules/user_oob.asm.in | $(COPYFAIL_BUILD)
	$(PYTHON) $(RULEGEN_DIR)/gen_rule.py --demo user_oob --arg-index 1 --max-len 4 --output-dir $(COPYFAIL_BUILD) --verify

$(COPYFAIL_BUILD)/libpatch_cache.$(SHARED_EXT): tests/workloads/userspace/copyfail/vuln_lib.c | $(COPYFAIL_BUILD)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) $(SHARED_FLAGS) $< -o $@

$(COPYFAIL_BUILD)/copyfail_app: tests/workloads/userspace/copyfail/app.c $(COPYFAIL_BUILD)/libpatch_cache.$(SHARED_EXT) | $(COPYFAIL_BUILD)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) $< -L$(COPYFAIL_BUILD) -lpatch_cache $(APP_RPATH) -o $@

$(COPYFAIL_BUILD)/libautoshield_copyfail.$(SHARED_EXT): $(USER_RUNTIME)/hook.c runtime/vm.c $(USER_RUNTIME)/safe_mem.c runtime/autoshield.h | $(COPYFAIL_BUILD)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) \
		-DHOOK_TARGET_ENTRY=patch_cache \
		-DHOOK_TARGET_SYMBOL=\"patch_cache\" \
		-DHOOK_DEFAULT_RULE=\"$(COPYFAIL_BUILD)/shadow.bin\" \
		$(SHARED_FLAGS) $(USER_RUNTIME)/hook.c runtime/vm.c $(USER_RUNTIME)/safe_mem.c $(DL_LIBS) -o $@

$(COPYFAIL_BUILD):
	mkdir -p $(COPYFAIL_BUILD)

$(USER_BUILD):
	mkdir -p $(USER_BUILD)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(USER_BUILD)/libvuln.$(SHARED_EXT): tests/workloads/userspace/basic/vuln_lib.c | $(USER_BUILD)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) $(SHARED_FLAGS) $< -o $@

$(USER_BUILD)/vuln_app: tests/workloads/userspace/basic/app.c $(USER_BUILD)/libvuln.$(SHARED_EXT) | $(USER_BUILD)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) $< -L$(USER_BUILD) -lvuln $(APP_RPATH) -o $@

$(USER_BUILD)/libautoshield_preload.$(SHARED_EXT): $(USER_RUNTIME)/hook.c runtime/vm.c $(USER_RUNTIME)/safe_mem.c runtime/autoshield.h | $(USER_BUILD)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) \
		-DHOOK_TARGET_ENTRY=vulnerable_copy \
		-DHOOK_TARGET_SYMBOL=\"vulnerable_copy\" \
		$(SHARED_FLAGS) $(USER_RUNTIME)/hook.c runtime/vm.c $(USER_RUNTIME)/safe_mem.c $(DL_LIBS) -o $@

safe-read-probe: $(BUILD_DIR)/safe_read_probe

$(BUILD_DIR)/safe_read_probe: tests/safe_read_probe.c $(USER_RUNTIME)/safe_mem.c runtime/autoshield.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(COMMON_CFLAGS) tests/safe_read_probe.c $(USER_RUNTIME)/safe_mem.c -o $@

test: test-security test-policy test-frontier test-robustness

frontier:
	$(PYTHON) -m tools.frontier $(ARGS)

test-frontier:
	PYTHONPATH="$(CURDIR):$${PYTHONPATH:-}" $(PYTEST) tests/test_frontier.py tests/test_frontier_soundness.py tests/test_frontier_returnflow.py tests/test_frontier_composition.py tests/test_frontier_types.py tests/test_frontier_benchmark.py

check:
	@bash -n tools/build_kernel_module.sh tools/export_artifacts.sh
	@$(MAKE) test

test-security:
	PYTHONPATH="$(CURDIR):$${PYTHONPATH:-}" $(PYTEST) tests/test_security.py

test-policy:
	PYTHONPATH="$(CURDIR):$${PYTHONPATH:-}" $(PYTEST) tests/test_policy_compiler.py

test-robustness:
	PYTHONPATH="$(CURDIR):$${PYTHONPATH:-}" $(PYTEST) tests/test_robustness.py

test-perf:
	PYTHONPATH="$(CURDIR):$${PYTHONPATH:-}" $(PYTEST) tests/test_perf.py

clean:
	rm -rf $(BUILD_DIR) eval/results/robustness_tmp eval/results/perf_user_workload.json
