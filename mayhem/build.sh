#!/usr/bin/env bash
# mayhem/build.sh — build aravis (meson) twice: a sanitized static library + libFuzzer harnesses,
# and a normal-flags build of upstream's own glib test suite for mayhem/test.sh.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Options shared by both builds: no viewer/gst/usb/introspection/docs (not fuzzed, extra deps).
# packet-socket is disabled so GigE Vision streams use plain UDP sockets.
MESON_OPTS=(-Ddefault_library=static -Dviewer=disabled -Dgst-plugin=disabled -Dusb=disabled
            -Dintrospection=disabled -Ddocumentation=disabled -Dpacket-socket=disabled)
# The fuzz build keeps upstream's default GVCP client timeout (500 ms x 5 retries,
# -Dfast-heartbeat=false): a loaded fuzzing host must never make the client give up on a reply the
# gvcp_device responder did send. The responder follows every reply with an error ack, so a
# malformed reply still ends the command at once instead of costing the timeout.
FUZZ_OPTS=(-Dfast-heartbeat=false)

# meson_setup <dir> <cflags> <ldflags> <extra opts...> — configure once, reconfigure on a re-run
# (idempotent; build dirs match upstream's gitignored `build-*/`).
meson_setup () {
  local dir="$1" cflags="$2" ldflags="$3"; shift 3
  if [ -f "$dir/build.ninja" ]; then
    CFLAGS="$cflags" LDFLAGS="$ldflags" meson setup --reconfigure "$dir" "${MESON_OPTS[@]}" "$@"
  else
    CFLAGS="$cflags" LDFLAGS="$ldflags" meson setup "$dir" "${MESON_OPTS[@]}" "$@"
  fi
}

# 1) Sanitized library (the fuzzed code is instrumented, DWARF 3).
FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
meson_setup build-fuzz "$FUZZ_CFLAGS" "$SANITIZER_FLAGS" -Dtests=false -Db_lundef=false "${FUZZ_OPTS[@]}"
ninja -C build-fuzz -j"$MAYHEM_JOBS" src/libaravis-0.10.a

# 2) Harnesses: libFuzzer binary + standalone reproducer each. --whole-archive keeps the
#    GResource constructor (embedded fake-camera XML) that nothing references by symbol.
DEPS_CFLAGS=$(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0 gmodule-2.0 libxml-2.0 zlib)
DEPS_LIBS=$(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 gmodule-2.0 libxml-2.0 zlib)
INCS="-I$SRC/src -I$SRC/build-fuzz/src"
LIB="-Wl,--whole-archive $SRC/build-fuzz/src/libaravis-0.10.a -Wl,--no-whole-archive"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$SRC/build-fuzz/lsan_off.o"
# netshim.c: a per-process loopback address for the GigE Vision harnesses (see the file).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/netshim.c" -o "$SRC/build-fuzz/netshim.o"
SHIM="$SRC/build-fuzz/lsan_off.o $SRC/build-fuzz/netshim.o -Wl,--wrap=getifaddrs"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SRC/build-fuzz/standalone_main.o"
for h in "$SRC"/mayhem/harnesses/fuzz_*.c; do
  name=$(basename "$h" .c)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $INCS $DEPS_CFLAGS "$h" \
      $SHIM $LIB $DEPS_LIBS -lm -lpthread -o "$SRC/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INCS $DEPS_CFLAGS "$h" "$SRC/build-fuzz/standalone_main.o" \
      $SHIM $LIB $DEPS_LIBS -lm -lpthread -o "$SRC/$name-standalone"
done

# 3) Upstream's test suite with NORMAL flags (no sanitizers) for mayhem/test.sh.
meson_setup build-tests "-O2 $COVERAGE_FLAGS" "$COVERAGE_FLAGS" -Dtests=true
ninja -C build-tests -j"$MAYHEM_JOBS" tests/evaluator tests/buffer tests/misc tests/dom tests/genicam tests/fake
