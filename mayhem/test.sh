#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests for gbl_root_canoe's host tools (built by mayhem/build.sh with
# normal flags into mayhem/out/). Test 1 is upstream's own submodules/ablfvextractor/tests/
# 001_test_extract.sh check (LinuxLoader.efi md5 from 001_myron_abl.elf); the others pin the
# patcher's and vbmetaport's output bytes on committed inputs (golden md5s) plus one negative case.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


OUT="$SRC/mayhem/out"
for b in extractfv patch_abl vbmetaport; do
  [ -x "$OUT/$b" ] || { echo "missing $OUT/$b — run mayhem/build.sh first" >&2; emit_ctrf "gbl-known-answer" 0 1; exit 1; }
done
W="$(mktemp -d "${TMPDIR:-/tmp}/gbl-test.XXXXXX")"
trap 'rm -rf "$W"' EXIT
pass=0; fail=0
check() {  # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1: expected '$2', got '$3'"; fail=$((fail+1)); fi
}
md5() { md5sum "$1" 2>/dev/null | awk '{print $1}'; }

# 1) upstream test 001: extract LinuxLoader.efi from the myron ABL ELF.
"$OUT/extractfv" "$SRC/submodules/ablfvextractor/tests/001_myron_abl.elf" -o "$W/ex" >/dev/null 2>&1
check extractfv_001_myron "993388c4312750c9bfd0df8aae8f1e11" "$(md5 "$W/ex/LinuxLoader.efi")"

# 2) scan summary of another ABL image.
check extractfv_info_nezha_global "Total PE Files Found: 2" \
  "$("$OUT/extractfv" -i "$SRC/ablrepo/nezha_global/abl.img" 2>/dev/null | grep '^Total PE Files Found')"

# 3) extract-all mode output bytes.
"$OUT/extractfv" -e all -o "$W/all" "$SRC/ablrepo/nezha_global/abl.img" >/dev/null 2>&1
check extractfv_all_nezha_global "5c51a65070596438d5dc32c77bcc2f7e" "$(md5 "$W/all/extracted_1.efi")"

# 4) patch the extracted myron LinuxLoader.efi: exact patched bytes.
"$OUT/patch_abl" "$W/ex/LinuxLoader.efi" "$W/patched.efi" > "$W/patch.log" 2>&1
check patch_abl_myron "a59df96ad4ca1ede3680aa9fee27da06" "$(md5 "$W/patched.efi")"
check patch_abl_myron_log "Boot patches: 1" "$(grep -m1 '^Boot patches:' "$W/patch.log")"

# 5) an image with no ABL boot-state code must be refused (non-zero exit, no output file).
head -c 65536 /dev/zero > "$W/zero.efi"
"$OUT/patch_abl" "$W/zero.efi" "$W/zero_out.efi" > "$W/zero.log" 2>&1; rc=$?
check patch_abl_reject_zero "1:absent" "$rc:$([ -e "$W/zero_out.efi" ] && echo present || echo absent)"

# 6) vbmetaport: transplant into an image with an existing AVB footer, and into one without.
T="$SRC/mayhem/tests"
"$OUT/vbmetaport" "$T/vbmeta_src.dat" "$T/target_footer.dat" "$W/o1.img" >/dev/null 2>&1
check vbmetaport_footer "3300edebfe9e038819d26e080da430e2" "$(md5 "$W/o1.img")"
"$OUT/vbmetaport" "$T/vbmeta_src.dat" "$T/target_plain.dat" "$W/o2.img" >/dev/null 2>&1
check vbmetaport_plain "ad38543f755f2390f22895af021cdc47" "$(md5 "$W/o2.img")"

emit_ctrf "gbl-known-answer" "$pass" "$fail"
