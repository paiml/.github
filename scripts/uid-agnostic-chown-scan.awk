# infra#2349 whole-file scan, one workflow file per run (called by test-uid-agnostic-chown.sh).
# Every chown/chgrp command word anywhere in the file (comments and echo text excluded) must be
# one of two approved shapes, and no chown/find line of its step may swallow an error.
#   A  the uid-agnostic self-heal find line (exact), step carries the marker comment
#   B  bare-metal `chown -R "$OWNER" "$WORK_ROOT"` with OWNER="$(id -un):$(id -gn)" in the same
#      step, followed by `; then` or `|| { echo "::error::..."; exit 1; }`, in a job with no container
# Prints FAIL[TAG] lines and one "SCAN <n>" line (chown commands examined).
# Constants arrive through the environment so the shell guard stays the single place they live.
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function unquote(s) { gsub(/"[^"]*"/, "\"\"", s); gsub(/'[^']*'/, "''", s); return s }
function fail(tag, ln, msg) { print "FAIL[" tag "] " F ":" ln ": " msg; bad = 1 }
BEGIN {
  FIND_A = ENVIRON["FIND_A"]; FIND_TAIL = ENVIRON["FIND_TAIL"]; MARK = ENVIRON["MARK"]
  OWN = ENVIRON["OWNER_LINE"]; CHOWN_B = ENVIRON["CHOWN_B"]
  sn = 0; total = 0; container = 0
}
function flush(   haveown, i, k, n, acc, start, raw, t, lg, ln, sw, u, cmd, nc, siteA, isB, pre, rest, ownother, text, hascmd) {
  if (sn == 0) return
  n = 0; acc = ""; start = 0; text = ""
  for (i = 1; i <= sn; i++) {
    raw = S[i]; t = trim(raw); text = text "\n" raw
    if (t ~ /^#/) continue
    if (acc == "") start = SN[i]
    if (t ~ /\\$/) { sub(/[ \t]*\\$/, "", t); acc = (acc == "" ? t : acc " " t); continue }
    acc = (acc == "" ? t : acc " " t)
    n++; LG[n] = acc; LN[n] = start; acc = ""
  }
  if (acc != "") { n++; LG[n] = acc; LN[n] = start }
  nc = 0; siteA = 0; ownother = 0; haveown = 0
  for (i = 1; i <= n; i++) {
    lg = LG[i]; ln = LN[i]; u = lg
    if (u ~ /^(echo|printf)[ \t]/) u = unquote(u)
    if (u ~ /^(- )?name:/ || u ~ /^(run|if|uses):/) cmd = 0
    else cmd = (u ~ /(^|[;&|({`[:space:]])(chown|chgrp)[ \t]/)
    if (lg == OWN) haveown = 1
    if (u ~ /(^|[ \t;])OWNER=/ && lg != OWN) ownother = 1
    if (!cmd) continue
    nc++; total++
    if (index(lg, "-exec sh -c") && index(lg, "chown -h \"$OWNER_UG\"")) {
      if (lg == FIND_A FIND_TAIL) siteA = 1
      else if (index(lg, FIND_A) == 1) fail("SWALLOW", ln, "the find site's failure tail was changed (must be the exact || { ::error::; exit 1; })")
      else if (index(lg, "-group") == 0) fail("GID", ln, "site selects by uid only: a file with the right uid and the wrong gid is never repaired")
      else fail("TARGET", ln, "site find/chown line differs from the ruled shape")
    } else if (index(lg, CHOWN_B)) {
      k = index(lg, CHOWN_B); pre = substr(lg, 1, k - 1); rest = substr(lg, k + length(CHOWN_B))
      isB = ((pre == "" || pre == "if ! sudo -n ") && (rest == "; then" || rest ~ /^ \|\| \{ echo "::error::[^"]*"; exit 1; \}$/))
      if (!isB) fail("TARGET", ln, "bare-metal chown is not the ruled shape: " lg)
      if (!haveown) fail("ASSIGN", ln, "OWNER is not assigned as " OWN " in this step")
      if (container) fail("TARGET", ln, "a container job runs as root: use the stat-derived owner, not id -un:id -gn")
    } else fail("TARGET", ln, "chown/chgrp is not the ruled owner on the ruled path: " lg)
  }
  if (nc > 0) {
    if (ownother) fail("ASSIGN", SN[1], "OWNER assigned from something other than " OWN)
    if (siteA && index(text, MARK) == 0) fail("UNMARKED", SN[1], "self-heal site without the \"" MARK "\" marker")
    for (i = 1; i <= n; i++) {
      lg = LG[i]; sw = unquote(lg)
      if (sw ~ /^(echo|printf)[ \t]/) continue
      if (sw ~ /(^|[^a-zA-Z_])set[ \t]+\+(e|o[ \t]+errexit)/) fail("SWALLOW", LN[i], "set +e in a step with a chown: " lg)
      if (lg !~ /(^|[;&|({`[:space:]])(chown|chgrp|find)[ \t]/) continue
      if (lg ~ /\|\|[ \t]*(true|:|\/bin\/true|\/usr\/bin\/true|echo)([ \t;)'"]|$)/ || sw ~ /\|\|[ \t]*printf([ \t;)]|$)/ || lg ~ /;[ \t]*true[ \t]*$/ || lg ~ /2>[ \t]*\/dev\/null/ || lg ~ /&>[ \t]*\/dev\/null/ || lg ~ />[ \t]*\/dev\/null[ \t]*2>&1/)
        fail("SWALLOW", LN[i], "error swallowed on a chown/find line: " lg)
    }
    for (i = 1; i <= sn; i++) if (S[i] ~ /^[ \t]*continue-on-error:/ && S[i] !~ /continue-on-error:[ \t]*false/) fail("SWALLOW", SN[i], "continue-on-error on a step with a chown")
  }
  sn = 0
}
/^  [A-Za-z0-9_.-]+:[ \t]*$/ { flush(); container = 0 }
/^    container:/ { container = 1 }
/^[ \t]*- (name|uses|run|id|if):/ { flush() }
{ sn++; S[sn] = $0; SN[sn] = NR }
END { flush(); print "SCAN " total; exit 0 }
