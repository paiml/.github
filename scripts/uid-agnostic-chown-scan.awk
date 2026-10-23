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
  if (K == "") K = F
  loadallow(ENVIRON["OPAQUE_ALLOW"])
  sn = 0; total = 0; container = 0
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
function cmdword(s,   n, a, i, m, T, j, st, w) {
  if (s ~ /(^|[;&|({])[ \t]*(\$\([^(]|`)/) return "$(...)"
  gsub(/\$\{/, "$", s); gsub(/\+?=\(/, "=X ", s); gsub(/[<>]\(/, ";", s); gsub(/\$\(/, ";", s); gsub(/`/, ";", s)
  n = split(s, a, /;|&&|\|\||\||&|\(|\{|\)/)
  for (i = 1; i <= n; i++) {
    st = trim(a[i]); if (st == "") continue
    m = split(st, T, /[ \t]+/); j = skipwrap(T, m, 1)
    if (j > m) continue
    w = T[j]
    if (w ~ /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/ || w ~ /^\$[0-9@*#?!]/ || w ~ /^\007/) return w
  }
  return ""
}
# nonlit(a): is the argument of eval / sh -c / source something the scanner cannot read? A word that
# starts with a single quote is literal text; otherwise any $, ` or $( ) outside single quotes is not.
# maskall(s): hide the shell separators that sit inside quotes (echo "... ($x) ...") so cmdword() does not
# read quoted text as a statement; a quoted word that STARTS with one ("$(tool)", "`tool`") stays visible.
function maskall(s,   i, c, q, o, sp, SQ, PD) {
  q = ""; o = ""; sp = 0
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (q == "'") { if (c == "'") q = ""; else if (c ~ /[;&|(){}`<>]/) c = "\007" }
    else if (q == "\"") {
      if (c == "\"") q = ""
      else if (c == "$" && substr(s, i + 1, 1) == "(") { sp++; SQ[sp] = q; PD[sp] = 1; q = ""; o = o c "("; i++; continue }   # "$(...)": a fresh context
      else if (c ~ /[;&|(){}`<>]/) c = "\007"
    } else if (c == "'" || c == "\"") q = c
    else if (sp > 0) {
      if (c == "(") PD[sp]++
      else if (c == ")") { PD[sp]--; if (PD[sp] == 0) { q = SQ[sp]; sp-- } }
    }
    o = o c
  }
  return o
}
function nonlit(a) {
  a = trim(a); if (a ~ /^'/) return 0
  gsub(/'[^']*'/, "", a)
  return (a ~ /[$`\001]/)
}
# walk(s, d): s is a kq() line (quotes kept). Sets PRIM (ownership primitive other than chown/chgrp,
# which the command-word regex already catches) and OPAQ (eval / sh -c / source with a non-literal
# argument). A literal eval / sh -c argument is scanned again, one level down.
#
# CLASS RULE (applies to EVERY run step, ownership or not). OPAQ is set for:
#   (a) a shell (sh bash dash zsh ksh ash) given -c anywhere among its flags (-o pipefail -c,
#       -eo pipefail -c, -lc ...) whose command string is not a literal;
#   (b) any pipe into a shell, into eval, into `xargs sh`, or into source /dev/stdin;
#   (c) eval, source or . with a non-literal argument (or reading /dev/stdin / a process substitution);
#   (d) a command word that is not a literal after normalisation: $'...' ANSI-C (here), and
#       $( ) / ` ` / $VAR words (cmdword() in flush()).
# unmask(): put back the | that maskpipe() hid inside quotes. maskpipe(): a | inside '...' or "..." is
# text (grep -E 'a|b'), not a pipe.
function unmask(s) { gsub(/\004/, "|", s); return s }
function maskpipe(s,   i, c, q, o) {
  q = ""; o = ""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (q == "" && (c == "'" || c == "\"")) q = c
    else if (q != "" && c == q) q = ""
    else if (q != "" && c == "|") c = "\004"
    o = o c
  }
  return o
}
# firstword(a): the first shell word of a (quote-aware): a '...' or "..." word runs to its closing quote.
function firstword(a,   q, e) {
  a = trim(a); q = substr(a, 1, 1)
  if (q == "'" || q == "\"") { e = index(substr(a, 2), q); return (e ? substr(a, 1, e + 1) : a) }
  sub(/[ \t].*$/, "", a); return a
}
function walk(s, d,   n, a, i, st, m, R, N, j, k, w, args, sc, piped, f) {
  if (d > 3) return
  s = maskpipe(unmask(s))
  if (s ~ /(^|[;&|({ \t])(source|\.)[ \t]+<\(/) OPAQ = 1                      # (c) source <(cmd)
  gsub(/(^|[ \t])-(exec|execdir|ok|okdir)[ \t]/, " ; ", s)
  gsub(/\{\}/, "@@", s)
  gsub(/\$\(|`/, " \001; ", s); gsub(/\$\{/, "$", s); gsub(/[<>]\(/, ";", s)
  gsub(/\|\|/, ";", s); gsub(/\|&?/, ";\002", s)
  n = split(s, a, /;|&&|&|\(|\{|\)/)
  for (i = 1; i <= n; i++) {
    st = a[i]; piped = (substr(st, 1, 1) == "\002"); if (piped) st = substr(st, 2)
    st = trim(st); if (st == "") continue
    m = split(st, R, /[ \t]+/)
    for (j = 1; j <= m; j++) N[j] = qs(R[j])
    j = skipwrap(N, m, 1)
    while (j <= m && N[j] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) j++
    if (j > m) continue
    w = bn(N[j])
    if (R[j] ~ /^\$'/ || R[j] ~ /^\$"/) OPAQ = 1          # (d) $'\x63hown' ANSI-C word
    if (w == "install") {
      for (k = j + 1; k <= m; k++) if (N[k] ~ /^-[A-Za-z]*[og]([^A-Za-z-].*)?$/ || N[k] ~ /^--(owner|group)(=|$)/) { addprim(w " " N[k], st); break }
    } else if (w == "cp" || w == "rsync" || w == "tar" || w == "mv") {
      for (k = j + 1; k <= m; k++) if (N[k] ~ /^--(chown|owner|group|same-owner|owner-map|group-map|usermap|groupmap)(=|$)/) { addprim(w " " N[k], st); break }
    } else if (w == "setfacl") addprim(w, st)
    else if (w == "eval" || w == "source" || w == ".") {
      args = ""; for (k = j + 1; k <= m; k++) args = args " " R[k]
      if (piped) OPAQ = 1          # (b) | eval, | source; source <(...)
      else if (args ~ /\/dev\/(stdin|fd\/|tty)|\/proc\/self\/fd|[ \t]-([ \t]|$)/) OPAQ = 1   # source /dev/stdin
      else if (w != "eval" && nonlit(args)) OPAQ = 1
      else if (w == "eval") { if (nonlit(args)) OPAQ = 1; else walk(qs(args), d + 1) }
    } else if (w ~ /^(sh|bash|dash|zsh|ksh|ash)$/) {
      sc = 0
      # (a) -c may follow any flags, including option arguments: -o pipefail -c, -eo pipefail -c
      for (k = j + 1; k <= m && N[k] ~ /^[-+]/; k++) {
        f = N[k]
        if (f == "--") break
        if (f ~ /^-[A-Za-z]*c[A-Za-z]*$/) { sc = k + 1; break }
        if (f ~ /^[-+][A-Za-z]*[oO]$/ || f ~ /^--(rcfile|init-file)$/) k++
      }
      if (sc) {
        args = ""; for (k = sc; k <= m; k++) args = args " " R[k]
        args = firstword(args)
        if (sc > m || nonlit(args)) OPAQ = 1
        else walk(qs(args), d + 1)
      } else if (piped) OPAQ = 1                    # (b) | sh, | bash -s, | xargs sh
    }
  }
}
# The allowlist (scripts/uid-agnostic-opaque-allow.txt, path in OPAQUE_ALLOW): `key:exact-line-text  # reason`,
# key = the workflow file name (actions: actions/NAME/action.yml), text = the trimmed logical line.
# The shell guard validates the file and fails a stale entry; the awk reports each entry it used.
function loadallow(file,   line, p, q, key) {
  if (file == "") return
  while ((getline line < file) > 0) {
    if (line ~ /^[ \t]*(#|$)/) continue
    p = 0; q = 0
    while ((q = index(substr(line, p + 1), " # ")) > 0) p += q
    if (p == 0) continue
    key = trim(substr(line, 1, p - 1)); ALLOW[key] = 1
  }
  close(file)
}
function allowed(lg,   k) { k = K ":" lg; if (k in ALLOW) { USED[k] = 1; return 1 } return 0 }
# a primitive aimed at the uid-agnostic owner_ug form is the only approved one
function addprim(what, st) { if (st !~ /OWNER_UG/) PRIM = (PRIM == "" ? "" : PRIM "; ") what }
# does the (normalised) step text deal with ownership at all?
function owns_step(t) { t = tolower(t); return (t ~ /chown|chgrp|owner_ug|setfacl|--same-owner|install[ \t][^\n]*(-o|-g|--owner|--group)/) }
# A variable command resolves when the step has at least one plain assignment to it and every
# assignment is a static word whose basename is not chown/chgrp. Anything dynamic does not resolve.
function resolves(w, text,   nm, n, L, i, v, found) {
  nm = w; gsub(/^\$\{?|\}?$/, "", nm); if (nm !~ /^[A-Za-z_][A-Za-z0-9_]*$/) return 0
  n = split(text, L, "\n"); found = 0
  for (i = 1; i <= n; i++) {
    v = trim(L[i]); sub(/^- /, "", v); sub(/^run:[ \t]*/, "", v); sub(/^(export|local|readonly|declare)[ \t]+/, "", v)
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
function flush(   haveown, i, k, n, acc, start, raw, t, lg, ln, sw, u, cmd, nc, siteA, isB, pre, rest, ownother, text, textn, hascmd, vcmd, vw, ku, nu, prim, opaq, nl, rm, runind, ind, startrun, LR, isown) {
  if (sn == 0) return
  n = 0; acc = ""; start = 0; text = ""; rm = 0; runind = 0
  for (i = 1; i <= sn; i++) {
    raw = S[i]; t = trim(raw); text = text "\n" raw
    ind = match(raw, /[^ \t]/) ? RSTART : 0
    if (raw ~ /^[ \t]*(- )?run:/) { match(raw, /run:/); runind = RSTART; rm = 1 }
    else if (rm && t != "" && t !~ /^#/ && ind <= runind) rm = 0
    if (t ~ /^#/) continue
    if (acc == "") { start = SN[i]; startrun = rm }
    if (t ~ /\\$/) { sub(/[ \t]*\\$/, "", t); acc = (acc == "" ? t : acc " " t); continue }
    acc = (acc == "" ? t : acc " " t)
    n++; LG[n] = acc; LN[n] = start; LR[n] = startrun; acc = ""
  }
  if (acc != "") { n++; LG[n] = acc; LN[n] = start; LR[n] = startrun }
  textn = qs(kq(text))
  nc = 0; siteA = 0; ownother = 0; haveown = 0
  for (i = 1; i <= n; i++) {
    lg = LG[i]; ln = LN[i]; u = lg
    sub(/^(- )?run:[ \t]*/, "", u)
    if (u ~ /^(echo|printf)[ \t]/) u = unquote(u)
    vcmd = 0; prim = 0; opaq = 0; PRIM = ""; OPAQ = 0
    ku = kq(u); nu = qs(ku)
    # INTREE (r6): the owner is never read from the tree being chowned. Any stat command, in any step of
    # any file, whose operand is a path inside the _work tree (RUNNER_TEMP, WORK_ROOT, the workspaces,
    # HOME, _temp, /__w, /github/*) is a failure; echo / printf text is not a command.
    if (lg !~ /^(- )?(name|if|uses):/ && u !~ /^(echo|printf)[ \t]/ && lg ~ /(^|[^A-Za-z_-])stat[ \t]/ && (lg ~ /RUNNER_TEMP|WORK_ROOT|GITHUB_WORKSPACE|RUNNER_WORKSPACE|\$HOME|\${HOME|_temp|_work|\/__w|\/github\//))
      fail("INTREE", ln, "stat of a path inside the chowned tree: " lg)
    if (lg ~ /^(- )?(name|if|uses):/) cmd = 0
    else {
      CHOWN_RE = "(^|[;&|({`\"'/[:space:]])(chown|chgrp)([ \t;&|)\"']|$)"
      cmd = (u ~ CHOWN_RE || nu ~ CHOWN_RE)
      walk(ku, 0)
      opaq = OPAQ
      if (!cmd && PRIM != "") { cmd = 1; prim = 1 }
      if (!cmd && u !~ /^(echo|printf)[ \t]/) {
        pre = u; gsub(/\\"/, "\005", pre); gsub(/\\'/, "\006", pre)
        vw = cmdword(qs(maskall(kq(pre)))); if (vw != "") { vcmd = 1; cmd = 1 }
      }
    }
    # CLASS RULE: no owns_step gate. Every run step is held to it; the only exemption is the allowlist file.
    if (opaq && LR[i] && !allowed(lg)) fail("OPAQUE", ln, "opaque shell (non-literal -c string, pipe into a shell / eval / source, eval or source of a non-literal, ANSI-C word): the scanner cannot see what will run: " lg)
    if (lg == OWN) haveown = 1
    if (u ~ /(^|[ \t;])OWNER=/ && lg != OWN) ownother = 1
    if (!cmd) continue
    nc++; total++
    if (prim) { fail("TARGET", ln, "ownership primitive (" PRIM ") is not the uid-agnostic owner_ug form: " lg); continue }
    if (vcmd) {
      # (d) a command word that is not a literal. A variable that every assignment in the step resolves
      # to a static non-chown word is a literal in effect; any other is OPAQUE in every run step (no
      # ownership-step gate), exempt only through the allowlist file.
      isown = (tolower(textn) ~ /chown|chgrp|owner_ug|owner=/ || owns_step(textn))
      if (resolves(vw, text)) { nc--; total-- }
      else {
        if (isown) fail("VARCMD", ln, "command word " vw " is a variable whose value cannot be resolved to a non-chown command: " lg)
        else { nc--; total-- }
        if ((LR[i] || isown) && !allowed(lg)) fail("OPAQUE", ln, "command word " vw " is not a literal after normalisation (variable / $( ) / printf-built): " lg)
      }
      continue
    }
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
      lg = LG[i]; sw = unquote(lg); nl = qs(kq(lg))
      if (sw ~ /^(echo|printf)[ \t]/) continue
      if (sw ~ /(^|[^a-zA-Z_])set[ \t]+\+(e|o[ \t]+errexit)/) fail("SWALLOW", LN[i], "set +e in a step with a chown: " lg)
      if (lg !~ /(^|[;&|({`"'\/[:space:]])(chown|chgrp|find)([ \t;&|)"']|$)/ && nl !~ /(^|[;&|({`\/[:space:]])(chown|chgrp|find)([ \t;&|)]|$)/) continue
      if (lg ~/\|\|[ \t]*(true|:|\/bin\/true|\/usr\/bin\/true|echo)([ \t;)'"]|$)/ || sw ~ /\|\|[ \t]*printf([ \t;)]|$)/ || lg ~ /;[ \t]*true[ \t]*$/ || lg ~ /2>[ \t]*\/dev\/null/ || lg ~ /&>[ \t]*\/dev\/null/ || lg ~ />[ \t]*\/dev\/null[ \t]*2>&1/)
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
END { flush(); for (k in USED) print "ALLOWUSED\t" k; print "SCAN " total; exit 0 }
