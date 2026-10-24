# infra#2349 whole-file scan, one workflow file per run (called by test-uid-agnostic-chown.sh).
# Every chown/chgrp command word anywhere in the file (comments and echo text excluded) must be
# one of two approved shapes, and no chown/find line of its step may swallow an error.
#   A  the uid-agnostic self-heal find line (exact), step carries the marker comment
#   B  bare-metal `chown -R "$OWNER" "$WORK_ROOT"` with OWNER="$(id -un):$(id -gn)" in the same
#      step, followed by `; then` or `|| { echo "::error::..."; exit 1; }`, in a job with no container
# Prints FAIL[TAG] lines and one "SCAN <n>" line (chown commands examined).
# Constants arrive through the environment so the shell guard stays the single place they live.
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
# unquote(): blank the quoted text of a message line. A double-quoted segment that holds an expansion ($( ) or a
# backtick) is EXECUTED text, so it is kept.
function unquote(s,   o, i, n, c, q, seg) {
  o = ""; n = length(s); i = 1
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "'") { q = index(substr(s, i + 1), "'"); if (q == 0) { o = o substr(s, i); break } o = o "''"; i += q + 1; continue }
    if (c == "\"") {
      q = i + 1; while (q <= n && substr(s, q, 1) != "\"") { if (substr(s, q, 1) == "\\") q++; q++ }
      seg = substr(s, i, q - i + 1)
      o = o ((seg ~ /\$\(|`/) ? seg : "\"\""); i = q + 1; continue
    }
    o = o c; i++
  }
  return o
}
function fail(tag, ln, msg) { print "FAIL[" tag "] " F ":" ln ": " msg; bad = 1 }
BEGIN {
  FIND_A = ENVIRON["FIND_A"]; FIND_TAIL = ENVIRON["FIND_TAIL"]; MARK = ENVIRON["MARK"]
  OWN = ENVIRON["OWNER_LINE"]; CHOWN_B = ENVIRON["CHOWN_B"]
  ALLOW_CMD = "^$NEVERMATCH"; sn = 0; total = 0; container = 0
}
# --- NORMALISE a command word the way the shell would, then match CLASSES, not spellings ---------
# kq(): remove backslashes and expand ${V:-w} ${V-w} ${V:=w} ${V=w} to w (quotes kept).
# qs(): remove quotes. A normalised word is qs(kq(word)); ch\own, 'ch'own, "ch""own", \chown and
# ${CHOWN:-chown} are all just chown after it. A word that still holds an unresolvable $, ` or $( )
# stays a variable command word (VARCMD, existing step scope).
function expdef(s,   tok, pre, post) {
  while (match(s, /\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=][^}]+\}/)) {
    tok = substr(s, RSTART, RLENGTH); pre = substr(s, 1, RSTART - 1); post = substr(s, RSTART + RLENGTH)
    sub(/^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]/, "", tok); sub(/\}$/, "", tok)
    s = pre tok post
  }
  return s
}
function kq(s) { gsub(/\\/, "", s); return expdef(s) }
function qs(s) { gsub(/["']/, "", s); return s }
function bn(s) { sub(/^.*\//, "", s); return s }
# Wrapper words that are stripped before the command word: sudo [-flags], doas, command, exec, env
# [VAR=..], nice, ionice, timeout N, xargs [-flags], nohup, setsid, time and shell keywords (do, then,
# if, while ...). T[] holds normalised tokens; returns the index of the first non-wrapper token.
function skipwrap(T, m, j,   t) {
  while (j <= m) {
    t = bn(T[j])
    if (t ~ /^(do|then|else|elif|if|while|until|time|!|nohup|setsid|builtin)$/) { j++; continue }
    if (t == "sudo" || t == "doas") { j++; while (j <= m && T[j] ~ /^-/) { if (T[j] ~ /^-[ughCDprtTU]$/) j++; j++ } continue }
    if (t == "command" || t == "exec") { j++; while (j <= m && T[j] ~ /^-/) j++; continue }
    if (t == "env") { j++; while (j <= m && (T[j] ~ /^-/ || T[j] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) j++; continue }
    if (t == "nice") { j++; while (j <= m && T[j] ~ /^-/) { if (T[j] == "-n") j++; j++ } continue }
    if (t == "ionice") { j++; while (j <= m && T[j] ~ /^-/) { if (T[j] ~ /^-[ctnp]$/) j++; j++ } continue }
    if (t == "timeout") { j++; while (j <= m && T[j] ~ /^-/) { if (T[j] ~ /^-[ks]$/) j++; j++ } if (j <= m && T[j] ~ /^[0-9.]+[smhd]?$/) j++; continue }
    if (t == "xargs") { j++; while (j <= m && T[j] ~ /^-/) { if (T[j] ~ /^-[nIPLsEda]$/ || T[j] ~ /^--(max-args|max-procs|replace|delimiter|arg-file|max-lines|max-chars|eof)$/) j++; j++ } continue }
    break
  }
  return j
}
# cmdword() returns the first command word of a statement of the (quote-stripped, normalised) line s
# that is a $variable / $( ) / backtick word ("" if none).
function cmdword(s,   ww, n, a, i, m, T, j, st, w) {
  if (s ~ /(^|[;&|({])[ \t]*(\$\([^(]|`)/) return "$(...)"
  gsub(/\$\{/, "$", s); gsub(/\+?=\(/, "=X ", s); gsub(/[<>]\(/, ";", s); gsub(/\$\(/, ";", s); gsub(/`/, ";", s)
  n = split(s, a, /;|&&|\|\||\||&|\(|\{|\)/)
  for (i = 1; i <= n; i++) {
    st = trim(a[i]); if (st == "") continue
    m = split(st, T, /[ \t]+/); j = skipwrap(T, m, 1)
    while (j <= m && T[j] ~ /^[A-Za-z_][A-Za-z0-9_]*\+?=/) j++
    if (j > m) continue
    w = T[j]
    # CLASS: any command word that holds an expansion ($, `) is a variable command word, whatever its
    # shape ($X, $X$Y, ${X}${Y}, pre$X, $X/bin/tool). Only a lone $VAR that the step resolves to a
    # static non-chown word (resolves()) or a word on the named allowlist below is let through.
    if (w ~ /[$`]/) { ww = w; sub(/^\002/, "", ww); sub(/\002$/, "", ww); if (ww ~ /\002/) ww = ww "~"; if (!(ww ~ ALLOW_CMD)) return ww }
  }
  return ""
}
# nonlit(a): is the argument of eval / sh -c / source something the scanner cannot read? A word that
# starts with a single quote is literal text; otherwise any $, ` or $( ) outside single quotes is not.
function nonlit(a) {
  a = trim(a); if (a ~ /^'/) return 0
  gsub(/'[^']*'/, "", a)
  return (a ~ /[$`\001]/)
}
# walk(s, d): s is a kq() line (quotes kept). Sets PRIM (ownership primitive other than chown/chgrp,
# which the command-word regex already catches) and OPAQ (eval / sh -c / source with a non-literal
# argument). A literal eval / sh -c argument is scanned again, one level down.
function walk(s, d,   n, a, i, st, m, R, N, j, k, w, args, sc) {
  if (d > 3) return
  gsub(/(^|[ \t])-(exec|execdir|ok|okdir)[ \t]/, " ; ", s)
  gsub(/\{\}/, "@@", s)
  gsub(/\$\(|`/, " \001; ", s); gsub(/\$\{/, "$", s); gsub(/[<>]\(/, ";", s)
  n = split(s, a, /;|&&|\|\||\||&|\(|\{|\)/)
  for (i = 1; i <= n; i++) {
    st = trim(a[i]); if (st == "") continue
    m = split(st, R, /[ \t]+/)
    for (j = 1; j <= m; j++) N[j] = qs(R[j])
    j = skipwrap(N, m, 1)
    while (j <= m && N[j] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) j++
    if (j > m) continue
    w = bn(N[j])
    if (w == "install") {
      for (k = j + 1; k <= m; k++) if (N[k] ~ /^-[A-Za-z]*[og]([^A-Za-z-].*)?$/ || N[k] ~ /^--(owner|group)(=|$)/) { addprim(w " " N[k], st); break }
    } else if (w == "cp" || w == "rsync" || w == "tar" || w == "mv") {
      for (k = j + 1; k <= m; k++) if (N[k] ~ /^--(chown|owner|group|same-owner|owner-map|group-map|usermap|groupmap)(=|$)/) { addprim(w " " N[k], st); break }
    } else if (w == "setfacl") addprim(w, st)
    else if (w == "eval" || w == "source" || w == ".") {
      args = ""; for (k = j + 1; k <= m; k++) args = args " " R[k]
      if (nonlit(args)) OPAQ = 1
      else if (w == "eval") walk(qs(args), d + 1)
    } else if (w ~ /^(sh|bash|dash|zsh|ksh|ash)$/) {
      sc = 0
      for (k = j + 1; k <= m && N[k] ~ /^-/; k++) if (N[k] ~ /^-[A-Za-z]*c$/) { sc = k + 1; break }
      if (sc) {
        args = ""; for (k = sc; k <= m; k++) args = args " " R[k]
        if (nonlit(args)) OPAQ = 1
        else walk(qs(args), d + 1)
      }
    }
  }
}
# An ownership primitive other than the two ruled chown shapes is never approved. A mention of OWNER_UG in the
# statement, in a comment or anywhere else, is NOT evidence: there is no exemption and no allowlist for this class.
function addprim(what, st) { PRIM = (PRIM == "" ? "" : PRIM "; ") what }
# does the (normalised) step text deal with ownership at all?
function owns_step(t) { t = tolower(t); return (t ~ /chown|chgrp|owner_ug|setfacl|--same-owner|install[ \t][^\n]*(-o|-g|--owner|--group)/) }
# A variable command resolves when the step has at least one plain assignment to it and every
# assignment is a static word whose basename is not chown/chgrp. Anything dynamic does not resolve.
function resolves(w, text,   nm, n, L, i, v, found) {
  nm = w; gsub(/^\$\{?|\}?$/, "", nm); if (nm !~ /^[A-Za-z_][A-Za-z0-9_]*$/) return 0
  n = split(text, L, "\n"); found = 0
  for (i = 1; i <= n; i++) {
    v = trim(L[i]); sub(/^- /, "", v); sub(/^run:[ \t]*/, "", v); sub(/^(export|local|readonly|declare)[ \t]+/, "", v)
    if (index(v, nm "+=") == 1 || index(v, nm "[") == 1) return 0
    if (index(v, nm "=") == 1) v = substr(v, length(nm) + 2)
    else if (index(v, nm ": ") == 1) v = substr(v, length(nm) + 3)
    else continue
    v = kq(v); gsub(/^["']|["']$/, "", v); sub(/[ \t;].*$/, "", v); gsub(/["']/, "", v)
    if (v == "" || v ~ /[$`]/) return 0
    sub(/^.*\//, "", v)
    if (v ~ /^(chown|chgrp|install|setfacl|cp|rsync|tar|mv|eval|source|\.|sh|bash|dash|zsh|ksh|ash)$/) return 0
    found = 1
  }
  return found
}
# --- EXIT shape (finding on de1f305): a fail-closed branch is matched as EXACT TEXT, never as a pattern -----
# The old rule only asked that the text from ::error:: to the end of the line finish with `; exit 1`, so
# `echo "::error::x"; exit 0; exit 1` (and return / true / : / a trap / `|| true` chaining / a second command /
# `exit 1` held in a comment or inside a string) passed. The only two accepted shapes are:
#   one line   <...> || { echo "::error::MSG"; exit 1; }      (or ...; rm -f "${CHOWN_FAILED:?}"; exit 1; })
#   multi-line echo "::error::MSG"  /  [rm -f "${CHOWN_FAILED:?}"]  /  exit 1  /  the branch close (fi, } or ;;)
# MSG is read by a quote-aware scanner (nested $( ) and "..." honoured); a backtick or an unclosed quote in MSG,
# or anything the scanner cannot classify, is RED. dqend(): s[i] is an opening ", returns the index of its closing
# ", or 0.
function dqend(s, i,   n, c) {
  n = length(s); i++
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "\\") { i += 2; continue }
    if (c == "`") return 0
    if (c == "\"") return i
    if (c == "$" && substr(s, i + 1, 1) == "(") { i = csend(s, i + 2); if (i == 0) return 0; continue }
    i++
  }
  return 0
}
# csend(): i is just after "$(" ; returns the index after the matching ")", or 0.
function csend(s, i,   n, c, d, q) {
  n = length(s); d = 1
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == "\\") { i += 2; continue }
    if (c == "'") { q = index(substr(s, i + 1), "'"); if (q == 0) return 0; i += q + 1; continue }
    if (c == "\"") { q = dqend(s, i); if (q == 0) return 0; i = q + 1; continue }
    if (c == "`") return 0
    if (c == "(") d++
    else if (c == ")") { d--; if (d == 0) return i + 1 }
    i++
  }
  return 0
}
# errshape(i, n): "" when every ::error:: on logical line i is in an approved fail-closed shape, else the reason.
function errshape(i, n,   lg, k, off, p, e, pre, rest, nx, RMF) {
  lg = LG[i]; off = 0; RMF = "rm -f \"${CHOWN_FAILED:?}\""
  if (lg ~ /^(- )?(name|if|uses|run|env|with):/) return "::error:: inside a YAML key line"
  while ((k = index(substr(lg, off + 1), "::error::")) > 0) {
    k += off; p = k - 6
    if (p < 1 || substr(lg, p, 6) != "echo \"") return "::error:: is not the start of an echo \"...\" statement"
    e = dqend(lg, p + 5)
    if (e == 0) return "the ::error:: message is not closed on this line or holds a backtick"
    off = e
    rest = substr(lg, e + 1)
    if (p == 1) {
      if (rest != "") return "something follows the ::error:: echo on its own line: " rest
      nx = i + 1
      if (nx <= n && LG[nx] == RMF) nx++
      if (nx > n || LG[nx] != "exit 1") return "the line after ::error:: is not exactly `exit 1` (nor the one approved rm -f then `exit 1`)"
      for (nx++; nx <= n && LG[nx] == ""; nx++) ;
      if (nx <= n && LG[nx] !~ /^(fi|\}|;;)$/) return "`exit 1` is not followed by the branch close (fi, } or ;;): " LG[nx]
    } else {
      pre = substr(lg, 1, p - 1)
      if (pre != "{ " && pre !~ /\|\| \{ $/) return "the ::error:: echo is not the first statement of a `|| { ...; }` group"
      sub(/\|\| \{ $/, "", pre)
      if (pre ~ /(^|[;&|({ \t])(true|:|exit 0|return( [0-9]+)?)[ \t]*$/) return "the `|| { ::error::; exit 1; }` group follows a command that cannot fail"
      if (rest != "; exit 1; }" && rest != "; " RMF "; exit 1; }" && rest != "; exit 1; }; }" && rest != "; " RMF "; exit 1; }; }") return "the group is not exactly `; exit 1; }` after the message: " rest
    }
  }
  return ""
}
function flush(   why, tq, ok, nx, haveown, i, k, n, acc, start, raw, t, lg, ln, sw, u, cmd, nc, siteA, isB, pre, rest, ownother, text, textn, hascmd, vcmd, vw, ku, nu, prim, opaq, nl) {
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
  textn = qs(kq(text))
  nc = 0; siteA = 0; ownother = 0; haveown = 0
  for (i = 1; i <= n; i++) {
    lg = LG[i]; ln = LN[i]; u = lg
    sub(/^(- )?run:[ \t]*/, "", u)
    # A message line is text, not a command, unless its output is PIPED somewhere: `printf 'chown ..' | sh` runs the
    # text, so a piped message keeps its quoted text and is classified like any other line (opaque scan: | sh is RED).
    if (u ~ /^(echo|printf)[ \t]/) { tq = unquote(u); if (tq ~ /(^|[^|])\|([^|]|$)/) tq = u; u = tq }
    vcmd = 0; prim = 0; opaq = 0; PRIM = ""; OPAQ = 0
    ku = kq(u); nu = qs(ku)
    # INTREE (r6): the owner is never read from the tree being chowned. Any stat command, in any step of
    # any file, whose operand is a path inside the _work tree (RUNNER_TEMP, WORK_ROOT, the workspaces,
    # HOME, _temp, /__w, /github/*) is a failure; echo / printf text is not a command.
    if (lg !~ /^(- )?(name|if|uses):/ && u !~ /^(echo|printf)[ \t]/ && lg ~ /(^|[^A-Za-z_-])stat[ \t]/ && (lg ~ /RUNNER_TEMP|WORK_ROOT|GITHUB_WORKSPACE|RUNNER_WORKSPACE|\$HOME|\${HOME|_temp|_work|\/__w|\/github\//))
      fail("INTREE", ln, "stat of a path inside the chowned tree: " lg)
    if (lg ~ /^(- )?(name|if|uses):/) cmd = 0
    else {
      CHOWN_RE = "(^|[;&|({`\"'/=[:space:]])(chown|chgrp)([ \t;&|)\"']|$)"
      cmd = (u ~ CHOWN_RE || nu ~ CHOWN_RE)
      walk(ku, 0)
      opaq = OPAQ
      if (!cmd && PRIM != "") { cmd = 1; prim = 1 }
      if (!cmd && u !~ /^(echo|printf)[ \t]/) { tq = ku; gsub(/["']/, "\002", tq); vw = cmdword(tq); if (vw != "") { vcmd = 1; cmd = 1 } }
    }
    if (opaq && owns_step(textn)) fail("OPAQUE", ln, "eval / sh -c / source with a non-literal argument in a step that deals with ownership: the scanner cannot see what will run: " lg)
    if (lg == OWN) haveown = 1
    if (u ~ /(^|[ \t;])OWNER=/ && lg != OWN) ownother = 1
    if (!cmd) continue
    nc++; total++
    if (prim) { fail("TARGET", ln, "ownership primitive (" PRIM ") is not the uid-agnostic owner_ug form: " lg); continue }
    if (vcmd) {
      # enforced only in a step that deals with ownership (names chown/chgrp/OWNER_UG/OWNER=/an ownership
      # primitive); another step's variable commands ("$PV" codegen, ...) are not an ownership question
      if ((tolower(textn) !~ /chown|chgrp|owner_ug|owner=/ && !owns_step(textn))) { nc--; total-- }
      else if (vw != "$(...)" && vw !~ /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/) fail("OPAQUE", ln, "command word " vw " holds an expansion that is not a lone resolvable $VAR (concatenated $X$Y, prefix$X, $X/tool ...) in a step that deals with ownership: the scanner cannot see what will run: " lg)
      else if (resolves(vw, text)) { nc--; total-- }
      else fail("VARCMD", ln, "command word " vw " is a variable whose value cannot be resolved to a non-chown command: " lg)
      continue
    }
    if (index(lg, "-exec sh -c") && index(lg, "chown -h \"$OWNER_UG\"")) {
      if (lg == FIND_A FIND_TAIL) siteA = 1
      else if (index(lg, FIND_A) == 1) fail("SWALLOW", ln, "the find site's failure tail was changed (must be the exact || { ::error::; exit 1; })")
      else if (index(lg, "-group") == 0) fail("GID", ln, "site selects by uid only: a file with the right uid and the wrong gid is never repaired")
      else fail("TARGET", ln, "site find/chown line differs from the ruled shape")
    } else if (index(lg, CHOWN_B)) {
      k = index(lg, CHOWN_B); pre = substr(lg, 1, k - 1); rest = substr(lg, k + length(CHOWN_B))
      isB = ((pre == "" && rest ~ /^ \|\| \{ echo "::error::[^"]*"; exit 1; \}$/) || (pre == "if ! sudo -n " && rest == "; then"))
      if (!isB) fail("TARGET", ln, "bare-metal chown is not the ruled shape: " lg)
      # `if ! sudo -n chown ...; then BODY fi` (r12): the body is NOT free text. It must be exactly one line, the plain
      # `chown -R "$OWNER" "$WORK_ROOT" || { echo "::error::MSG"; exit 1; }` (checked by the same exact-text errshape()
      # as every other fail-closed branch), then `fi`. A body of true / : / exit 0 / nothing / an echo, or a second
      # command, would let a failed sudo fall through with the tree unrepaired.
      if (isB && pre == "if ! sudo -n ") {
        b = LG[i + 1]; kb = index(b, CHOWN_B)
        if (i + 1 > n) fail("EXIT", ln, "the `if ! sudo -n chown ...; then` has no body: " lg)
        else if (kb != 1 || substr(b, length(CHOWN_B) + 1) !~ /^ \|\| \{ echo "::error::[^"]*"; exit 1; \}$/) fail("EXIT", ln, "the body of `if ! sudo -n chown ...; then` is not exactly the plain chown with its `|| { echo ::error::..; exit 1; }` branch: " b)
        else if ((why = errshape(i + 1, n)) != "") fail("EXIT", LN[i + 1], why ": " b)
        else if (LG[i + 2] != "fi") fail("EXIT", ln, "the `if ! sudo -n chown ...; then` body is not closed by `fi` straight after the plain chown: " LG[i + 2])
      }
      if (!haveown) fail("ASSIGN", ln, "OWNER is not assigned as " OWN " in this step")
      if (container) fail("TARGET", ln, "a container job runs as root: use the stat-derived owner, not id -un:id -gn")
    } else fail("TARGET", ln, "chown/chgrp is not the ruled owner on the ruled path: " lg)
  }
  if (nc > 0) {
    if (ownother) fail("ASSIGN", SN[1], "OWNER assigned from something other than " OWN)
    if (siteA && index(text, MARK) == 0) fail("UNMARKED", SN[1], "self-heal site without the \"" MARK "\" marker")
    for (i = 1; i <= n; i++) {
      lg = LG[i]; sw = unquote(lg); nl = qs(kq(lg))
      if (sw ~ /^(echo|printf)[ \t]/) continue
      if (sw ~ /(^|[^a-zA-Z_])set[ \t]+\+(e|o[ \t]+errexit)/) fail("SWALLOW", LN[i], "set +e in a step with a chown: " lg)
      if (sw ~ /(^|[;&|({ \t])trap[ \t]/) fail("EXIT", LN[i], "a trap in a step with a chown can rewrite the fail-closed exit status: " lg)
      if (lg !~ /(^|[;&|({`"'\/[:space:]])(chown|chgrp|find)([ \t;&|)"']|$)/ && nl !~ /(^|[;&|({`\/[:space:]])(chown|chgrp|find)([ \t;&|)]|$)/) continue
      if (lg ~/\|\|[ \t]*(true|:|\/bin\/true|\/usr\/bin\/true|echo)([ \t;)'"]|$)/ || sw ~ /\|\|[ \t]*printf([ \t;)]|$)/ || lg ~ /;[ \t]*true[ \t]*$/ || lg ~ /2>[ \t]*\/dev\/null/ || lg ~ /&>[ \t]*\/dev\/null/ || lg ~ />[ \t]*\/dev\/null[ \t]*2>&1/)
        fail("SWALLOW", LN[i], "error swallowed on a chown/find line: " lg)
    }
    # EXIT: every ::error:: in a step with a chown is a fail-closed path. errshape() matches the branch as
    # EXACT TEXT: the error echo, then `exit 1` alone (one approved rm -f may sit between), then the branch close;
    # or the one-line `|| { echo "::error::MSG"; [rm -f ...;] exit 1; }`. Anything else, including `exit 0`,
    # return, true, :, a second command, a `|| true` chain, `exit 1` in a comment or inside a string, is RED.
    for (i = 1; i <= n; i++) {
      if (index(LG[i], "::error::") == 0) continue
      why = errshape(i, n)
      if (why != "") fail("EXIT", LN[i], why ": " LG[i])
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
