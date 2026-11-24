#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer functional checks of proot (built by build.sh as out/proot-plain,
# upstream's normal flags). Each check runs a guest command under proot and compares its output
# with the value proot's emulation must produce (fake root, bind mounts, cwd, link2symlink,
# fake ownership, kompat uname, shebang exec). upstream's tests/ suite needs a prebuilt static
# rootfs and is documented as partly failing, so it is not used.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

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

P="$SRC/out/proot-plain"

[ -x "$P" ] || { echo "missing $P: build.sh did not run" >&2; emit_ctrf proot-known-answer 0 1; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/proot-test-XXXXXX")
trap 'rm -rf "$T"' EXIT
export PROOT_TMP_DIR="$T"
mkdir -p "$T/host" "$T/w"; echo hello-bind > "$T/host/f"

pass=0 fail=0
check() { # name expected cmd...
  local name="$1" want="$2"; shift 2
  local got; got=$("$@" 2>/dev/null)
  if [ "$got" = "$want" ]; then pass=$((pass+1)); echo "PASS $name";
  else fail=$((fail+1)); echo "FAIL $name: want [$want] got [$got]"; fi
}

check fake-root-uid    "0"            "$P" -0 id -u
check fake-root-gid    "0"            "$P" -0 id -g
check bind-mount       "hello-bind"   "$P" -b "$T/host:/proot-test-bind" cat /proot-test-bind/f
check bind-dir-listing "f"            "$P" -b "$T/host:/proot-test-bind" ls /proot-test-bind
check cwd              "$T/w"         "$P" -w "$T/w" pwd
check fake-chown       "ok 0:0"       "$P" -0 -w "$T/w" sh -c 'touch c; chown 123:456 c && printf "ok %s" "$(stat -c %u:%g c)"'
check link2symlink     "x 2"          "$P" -l -w "$T/w" sh -c 'echo x > a; ln a b; printf "%s %s" "$(cat b)" "$(stat -c %h a)"'
check kompat-uname     "3.0.0"        "$P" -k 3.0.0 uname -r
check exec-shebang     "arg1"         "$P" -w "$T/w" sh -c 'printf "#!/bin/sh\necho \$1\n" > s; chmod +x s; ./s arg1'

emit_ctrf proot-known-answer "$pass" "$fail"
