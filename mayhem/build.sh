#!/usr/bin/env bash
#
# mayhem/build.sh — build proot's fuzz targets and its functional-test build.
#
# proot is a ptrace-based tracer with no library API: its untrusted input is the program it is
# asked to run and that program's syscalls. Mayhem's sandbox does not allow ptrace, so every
# target runs out/proot-replay: proot's own objects (ASan+UBSan halting, AFL++ instrumentation,
# Mayhemfiles use `afl: true`) linked with mayhem/harnesses/replay_main.c, which parses proot's
# real command line and replays the input's syscalls through proot's translator against a
# simulated tracee (or, in mode `exec`, an execve() of the input file).
#
# Outputs (all under /mayhem/out):
#   out/proot-replay   the fuzz target of every Mayhemfile (its own reproducer)
#   out/proot          the same instrumented proot as a normal tracer (for local reproduction)
#   out/proot-plain    proot with upstream's normal flags, for mayhem/test.sh
#
# The loader (src/loader) is a freestanding -nostdlib stub that proot injects into the guest; it
# cannot link sanitizer or coverage runtimes, so in the fuzz build it is built first with plain
# flags and the rest of proot afterwards with the fuzz flags (make does not rebuild the loader then).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${AFL_CC:=afl-clang-fast}"
export SANITIZER_FLAGS DEBUG_FLAGS CC MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
mkdir -p out
# upstream's makefile builds in tree only (its out-of-tree VPATH mode doubles source paths), so
# the two proot builds run one after the other in src/, each from a `make clean` tree (objects
# are gitignored by upstream's .gitignore).
LOADERS="loader/loader-wrapped.o loader/loader-m32-wrapped.o"

# 1) Plain proot (upstream's own flags) for the functional oracle.
make -C src clean >/dev/null
make -C src -j"$MAYHEM_JOBS" CC="$CC" CFLAGS="-Wall -Wextra -O2 $COVERAGE_FLAGS" \
     LDFLAGS="-ltalloc -Wl,-z,noexecstack $COVERAGE_FLAGS" proot
cp src/proot out/proot-plain

# 2) The fuzz target. UBSan's `function` check is relaxed (only that check, ASan and the rest of
#    UBSan stay halting): execve/aoxp.c calls its xpointee helpers through a generic
#    `int (*)(ArrayOfXPointers *, ...const void *)` table, so every execve of a script/ELF that
#    proot rewrites (shebang, loader argv) aborts on that benign cast and the exec target could
#    not get past it. `pointer-overflow` is relaxed too: tracee/mem.c's read_string/read_data/
#    write_data compute `src + offset` before the (simulated) process_vm_readv/PEEKDATA, so
#    every guest NULL pointer argument aborted on "applying zero offset to null pointer" before
#    the translator did anything with it. NULL+0 is benign there: the access itself fails with
#    EFAULT, as the kernel's does.
UBSAN_RELAX="-fno-sanitize=function,pointer-overflow"
#    The fuzz target: loader with plain flags, then proot with AFL + sanitizers + DWARF 3.
make -C src clean >/dev/null
make -C src -j"$MAYHEM_JOBS" CC="$CC" CFLAGS="-O2" $LOADERS
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.c -o out/lsan_off.o
AFL_QUIET=1 make -C src -j"$MAYHEM_JOBS" CC="$AFL_CC" \
     CFLAGS="-O1 $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS" \
     LDFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $SRC/out/lsan_off.o -ltalloc -Wl,-z,noexecstack" proot

# 3) The replay harness (the fuzz target of every Mayhemfile). Mayhem's sandbox does not allow
#    ptrace, so instead of tracing a guest, mayhem/harnesses/replay_main.c replays the input's
#    syscalls through proot's own translate_syscall() with a simulated tracee. It links the very
#    objects just built (AFL + ASan + UBSan) with these symbol redirections (objcopy):
#      every object: ptrace, process_vm_readv/writev, kill, fork -> fz_* (simulated tracee)
#      cli/cli.o:    main -> proot_main, launch_process/event_loop -> fz_* (replay instead of fork)
OBJS=$(make -s -C src --eval 'print-objs: ; @echo $(OBJECTS)' print-objs)
rm -rf out/replay-objs && mkdir -p out/replay-objs
REDIR="--redefine-sym ptrace=fz_ptrace --redefine-sym process_vm_readv=fz_process_vm_readv
       --redefine-sym process_vm_writev=fz_process_vm_writev --redefine-sym kill=fz_kill
       --redefine-sym fork=fz_fork"
LINK_OBJS=()
for o in $OBJS; do
  d="out/replay-objs/${o//\//_}"
  case "$o" in
    loader/*) cp "src/$o" "$d" ;;
    cli/cli.o) objcopy $REDIR --redefine-sym main=proot_main \
                 --redefine-sym launch_process=fz_launch_process \
                 --redefine-sym event_loop=fz_event_loop "src/$o" "$d" ;;
    *) objcopy $REDIR "src/$o" "$d" ;;
  esac
  LINK_OBJS+=("$d")
done
AFL_QUIET=1 "$AFL_CC" -O1 $SANITIZER_FLAGS $UBSAN_RELAX $DEBUG_FLAGS \
     -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -Isrc -c mayhem/harnesses/replay_main.c -o out/replay_main.o
AFL_QUIET=1 "$AFL_CC" $SANITIZER_FLAGS $DEBUG_FLAGS -o out/proot-replay out/replay_main.o \
     "${LINK_OBJS[@]}" out/lsan_off.o -ltalloc -Wl,-z,noexecstack
[ -x out/proot-replay ]
cp src/proot out/proot
