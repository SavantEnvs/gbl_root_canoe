#!/usr/bin/env bash
#
# mayhem/build.sh — build gbl_root_canoe's host tools as fuzz harnesses + their functional test binaries.
#
# Upstream builds each host tool as a single gcc command (submodules/patcher/Makefile,
# submodules/ablfvextractor/Makefile, tools/vbmetafixer/*.c); there is no library. We do the same
# with the base image's clang:
#   1. the fuzzed sources compiled with $SANITIZER_FLAGS $DEBUG_FLAGS into each libFuzzer harness and
#      its -standalone reproducer (out/<fuzzer>, out/<fuzzer>-standalone);
#      plus two of the custom UEFI parsers (ENTRIES.CFG list, PE/Authenticode verifier) host-compiled;
#   2. the upstream CLIs (patch_abl, extractfv, vbmetaport) with NORMAL flags (-O2) for mayhem/test.sh.
# Everything lands in mayhem/out/ (gitignored by mayhem/.gitignore), so re-runs and a
# `git clean -ffdX`-ed tree rebuild from scratch. No network access is needed (liblzma-dev is an apt
# package in the image).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"
OBJ="$OUT/obj"
rm -rf "$OUT"
mkdir -p "$OBJ"

FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1"
H="$SRC/mayhem/harnesses"
PATCHER="$SRC/submodules/patcher"
mapfile -t PATCHER_SRCS < <(find "$PATCHER/src" -name '*.c' ! -name patch_abl.c | LC_ALL=C sort)

# lsan_off + the standalone driver, compiled once.
$CC $FUZZ_CFLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OBJ/lsan_off.o"
$CC $FUZZ_CFLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

# link_both <name> <extra args...>: the libFuzzer binary and its -standalone reproducer.
link_both() {
  local name="$1"; shift
  $CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "$@" "$OBJ/lsan_off.o" -o "$OUT/$name"
  $CC $FUZZ_CFLAGS "$OBJ/standalone_main.o" "$@" "$OBJ/lsan_off.o" -o "$OUT/$name-standalone"
}

# 1a) patch_abl: PatchBuffer() over all patcher sources except the CLI main.
link_both fuzz_patch_abl -I"$PATCHER/include" "$H/fuzz_patch_abl.c" "${PATCHER_SRCS[@]}"
# 1b) extractfv: the tool's single TU, #included by the harness (main renamed).
link_both fuzz_extractfv "$H/fuzz_extractfv.c" -llzma
# 1c) vbmetaport is NOT a fuzz target: the whole tool is ~280 lines (main -> transplant_vbmeta ->
#     read_avb_footer/verify_avb_header/create_avb_footer, ~48 Mayhem edges with every function
#     reached), so a dedicated target adds nothing a campaign would grow. Its CLI is still built
#     below for mayhem/test.sh.

# 1d/1e) super-fastboot UEFI parsers, host-compiled against the in-tree EDK2 MdePkg headers
#        (-fshort-wchar: EDK2's CHAR16 L"" literals) with the few BaseLib/BaseMemoryLib calls they make
#        provided by mayhem/harnesses/sfb_host_stubs.c. DEBUG() is compiled out (MDEPKG_NDEBUG).
EDK2="$SRC/submodules/uefi/edk2"
LL="$EDK2/QcomModulePkg/Application/LinuxLoader"
SECLIB="$EDK2/QcomModulePkg/Library/SfbSecurityLib"
MBED="$EDK2/CryptoPkg/Library/MbedTlsLib/mbedtls"
UEFI_INC=(-fshort-wchar -Wno-macro-redefined -DMDEPKG_NDEBUG -I"$EDK2/MdePkg/Include" -I"$EDK2/MdePkg/Include/X64")
link_both fuzz_sfb_entries "${UEFI_INC[@]}" -I"$LL" \
  "$H/fuzz_sfb_entries.c" "$H/sfb_host_stubs.c" "$LL/SuperFbEntryList.c"

# mbedtls (vendored copy the firmware links, default upstream config).
# -fno-sanitize=alignment on this target only: SfbPeVerify.c reads the security data directory
# through a `CONST PE_DATA_DIR *` at an attacker-chosen (odd) offset (SfbPeVerify.c:243), so UBSan's
# alignment check fires on almost every mutated image and blocks the rest of the verifier. That
# misaligned access is recorded as a finding in the integration PR; ASan and all other UBSan checks stay on.
PEV_FLAGS="$FUZZ_CFLAGS -fno-sanitize=alignment"
# The modules that parse the image's attacker-controlled WIN_CERTIFICATE / PKCS#7 blob (PKCS#7,
# X.509, ASN.1, OIDs, public keys, RSA signature check, digest dispatch) are fuzzed code: they get
# the sanitizers AND SanCov, so the fuzzer can steer into the signature parser. Two copies: one with
# -fsanitize=fuzzer-no-link for the libFuzzer binary, one plain for the -standalone reproducer.
MBED_FUZZED=(pkcs7 x509 x509_crt x509_crl asn1parse oid pk pkparse pk_wrap rsa md)
mkdir -p "$OBJ/mbedtls" "$OBJ/mbedtls_fz" "$OBJ/mbedtls_sa"
for m in "${MBED_FUZZED[@]}"; do
  $CC $PEV_FLAGS -fsanitize=fuzzer-no-link -I"$MBED/include" -I"$MBED/library" -c "$MBED/library/$m.c" -o "$OBJ/mbedtls_fz/$m.o"
  $CC $PEV_FLAGS -I"$MBED/include" -I"$MBED/library" -c "$MBED/library/$m.c" -o "$OBJ/mbedtls_sa/$m.o"
done
# The rest of mbedtls (bignum, hashes, ciphers, PSA, TLS) is a dependency: built without
# sanitizers/coverage (SPEC §6.2 item 19), with -gdwarf-3, into a static archive under out/.
skip_re="^($(IFS='|'; echo "${MBED_FUZZED[*]}"))\.c$"
find "$MBED/library" -maxdepth 1 -name '*.c' -print0 | LC_ALL=C sort -z |
  xargs -0 -P "$MAYHEM_JOBS" -I{} sh -c 'echo "$(basename "$3")" | grep -Eq "$5" && exit 0; $0 -O2 $1 -I"$2/include" -I"$2/library" -c "$3" -o "$4/$(basename "$3" .c).o"' \
    "$CC" "$DEBUG_FLAGS" "$MBED" {} "$OBJ/mbedtls" "$skip_re"
rm -f "$OBJ/libmbedtls_dep.a"
ar rcs "$OBJ/libmbedtls_dep.a" "$OBJ"/mbedtls/*.o
PEV_ARGS=(-fno-sanitize=alignment "${UEFI_INC[@]}" -I"$EDK2/QcomModulePkg/Include" -I"$SECLIB" -I"$MBED/include" -I"$H"
  "$H/fuzz_sfb_pe_verify.c" "$H/sfb_cert_pool.c" "$H/sfb_host_stubs.c" "$SECLIB/SfbPeVerify.c")
$CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE "${PEV_ARGS[@]}" "$OBJ"/mbedtls_fz/*.o "$OBJ/libmbedtls_dep.a" \
  "$OBJ/lsan_off.o" -o "$OUT/fuzz_sfb_pe_verify"
$CC $FUZZ_CFLAGS "$OBJ/standalone_main.o" "${PEV_ARGS[@]}" "$OBJ"/mbedtls_sa/*.o "$OBJ/libmbedtls_dep.a" \
  "$OBJ/lsan_off.o" -o "$OUT/fuzz_sfb_pe_verify-standalone"

# 2) Upstream CLIs with normal flags (the functional-test oracle build; no sanitizers).
$CC -O2 $COVERAGE_FLAGS -I"$PATCHER/include" -o "$OUT/patch_abl" "${PATCHER_SRCS[@]}" "$PATCHER/src/patch_abl.c"
$CC -O2 $COVERAGE_FLAGS -o "$OUT/extractfv" "$SRC/submodules/ablfvextractor/extractfv.c" -llzma
$CC -O2 $COVERAGE_FLAGS -o "$OUT/vbmetaport" "$SRC/tools/vbmetafixer/vbmetaport.c"

rm -rf "$OBJ"
ls -l "$OUT"
