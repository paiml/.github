# infra#2349 OPAQUE class scan, one workflow / composite-action file per run (called by
# test-uid-agnostic-chown.sh). Closes the class behind three scanner holes found at f0e60da:
#   X+=own appends, `alias c=chown`, and "$X$Y" in a step with no chown token.
# CAPABILITY RULES (PMAT-2359): judged by what the code can do, never by how a command is spelled.
#   - awk/gawk/mawk/nawk are interpreters: RED [INTERP] for a program using system(, a pipe to or from a
#     command (print |, | getline, |&), @ (gawk directives), a program from -f/-E/-i/-l/-W or --file/--exec/
#     --include/--load, or a program text that is dynamic ($, backtick, ${{ }}). Plain text-processing awk is green.
#     perl, ruby, node, lua, tclsh and the other embedded languages are interpreters too.
#   - github-script (or any step with a script: key): RED [JS] for child_process / exec / spawn / @actions/exec,
#     any chown-like name, eval / Function / constructor / Reflect / import(), a non-literal require, or dynamic
#     property access (X[expr]); uses: docker:// and runs.using node|docker are RED (code not read).
#   Exceptions only through a committed allowlist row (exact step and line, with a reason).
#
# RULE. In EVERY shell run step of the file, every command word must be a plain literal word
# (letters, digits and _ . / + : @ % , = ~ -, or one whole quoted word of those). RED [OPAQUE] when it is not:
#   - a word with $, a backtick, a backslash, a glob, quote-concatenation or a ${{ }} expression;
#   - a lone $VAR / ${VAR} / "$VAR" unless the step assigns it exactly once, by a plain `VAR=literal`
#     (no +=, no second assignment, no read/for/printf -v/${VAR:=}/(( )) binding) before the use, and the
#     literal is itself not eval / alias / source / a shell / trap;
#   - eval and alias (always), source / `.` of a path that is not a plain literal, sh|bash -c or trap with a
#     payload that is not a literal string (a literal payload is scanned again, one level down);
#   - a function definition (it can shadow a command by name).
# Text that is not shell is skipped BEFORE the rule runs: only the `run:` block of a step with a bash/sh
# shell is read (github-script bodies and every other block scalar are skipped), single- and double-quoted
# strings (awk / jq / sed programs given as literals) are arguments, heredoc bodies are data (a heredoc fed
# to a shell, and every $( ) or backtick inside any heredoc, is scanned), and each ${{ }} expression is
# replaced by a placeholder word (a placeholder in command position is RED).
# A RED word is let through only by a row of the committed allowlist (env ALLOW):
#   file<TAB>step name<TAB>trimmed physical line<TAB>reason        (all four fields, reason not empty)
# Output: FAIL[<tag>] lines (OPAQUE, INTERP, TARGET, SHELL, UNPARSE, PRIM), "ALLOWUSED <key>" per row that matched, and
# "OSCAN <seen> <scanned> <unparseable> <words> <allowed>".
# STEP RULES (r4, closing the third and fourth rounds of parser holes at 3346687). Where the scanner cannot classify
# something with certainty it fails closed: RED, or a committed allowlist row with a reason. Never a silent skip.
#   - EVERY entry of every `steps:` list is counted. seen = scanned + unparseable is asserted by the caller. A
#     flow mapping / flow sequence step, a `steps:` that is not a block sequence, an anchor, an alias, a merge key, a
#     quoted or non-plain step key, a duplicate run/shell key, a second YAML document, or a `run:` outside a steps
#     list is UNPARSEABLE and RED.
#   - `shell:` may be absent, bash, sh, or an exact GitHub default form (bash -e {0}, sh -e {0}, bash --noprofile
#     --norc -eo pipefail {0}). Any other value (here or in defaults.run.shell) is RED [SHELL]; the step is scanned anyway.
#   - Ownership primitives are found in EVERY statement of EVERY step, at ANY token position (so a wrapper, a quoted
#     payload or a neighbouring comment changes nothing): tar/cpio/pax --owner --group --same-owner, install -o -g,
#     cp/rsync/mv --chown --owner --group, setfacl, chmod aimed at the work tree or at an operand it cannot read.
#     A comment is stripped by the lexer and is never evidence. A mention of OWNER_UG exempts nothing. [TARGET]
#   - Text fed to an interpreter is RED [INTERP]: `| sh`, `| bash`, `| eval`, a here-string or heredoc to a shell,
#     `bash -s`, `bash -`, `bash <(...)`, `sh /dev/stdin`, a shell with no -c and no script, a shell run on a script
#     FILE (the file may have been written by the step), eval, source / `.`, a command word that is a relative path or
#     an absolute path outside the system directories, and xargs -I replacement into a shell.
#   - A non-shell block (github-script body, with: value) that names chown / chgrp / setfacl is RED [PRIM].
function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
function bn(s) { sub(/^.*\//, "", s); return s }
function shown(w) { gsub(/\003/, "", w); return w }
function indent(s,   t) { t = s; sub(/^[ \t]*/, "", t); return length(s) - length(t) }
# lit(w): the plain literal text of word w, or "" if w is not a plain literal word
function lit(w,   x) {
  if (w ~ /^[A-Za-z0-9_.\/+:@%,=~-]+$/) return w
  if (w == "[" || w == "[[" || w == "]]" || w == "!" || w == "{" || w == "}" || w == ":") return w
  if (w ~ /^"[^"$`\\\003]+"$/ || w ~ /^'[^']+'$/) { x = substr(w, 2, length(w) - 2); if (x ~ /^[A-Za-z0-9_.\/+:@%,=~-]+$/) return x }
  return ""
}
# unq(w): the text of a whole-word literal string payload ('...' or "..." with no expansion), else SENTINEL
function unq(w) {
  if (w ~ /^'[^']*'$/ || w ~ /^"[^"$`\\\003]*"$/) return substr(w, 2, length(w) - 2)
  return "\001"
}
# redt(): RED with a tag, let through only by an exact allowlist row. hard(): RED with no allowlist at all.
function redt(tag, ln, msg,   key) {
  key = FK "\t" STEP "\t" trim(FL[ln])
  if (key in ALLOW) { USED[key] = 1; allowed++; return }
  print "FAIL[" tag "] " F ":" ln ": " msg ": " trim(FL[ln]); bad = 1
  print "ROW\t" key "\t<reason>"
}
function red(ln, msg) { redt("OPAQUE", ln, msg) }
function hard(tag, ln, msg) { print "FAIL[" tag "] " F ":" ln ": " msg ": " trim(FL[ln])  " (no allowlist for this class)"; bad = 1 }
# pseudo(): a construct that stands in for steps the reader cannot enumerate: counted as one seen + one unparseable
function pseudo(ln, msg) { SEEN++; UNPARSE++; redt("UNPARSE", ln, msg) }
# matchparen(s, p): index of the ")" closing the "(" at p (length+1 when unmatched)
function matchparen(s, p,   n, k, c, d, q) {
  n = length(s); d = 0
  for (k = p; k <= n; k++) {
    c = substr(s, k, 1)
    if (c == "\\") { k++; continue }
    if (c == "'") { q = index(substr(s, k + 1), "'"); if (q == 0) return n + 1; k += q; continue }
    if (c == "\"") {
      for (k++; k <= n; k++) {
        c = substr(s, k, 1)
        if (c == "\\") { k++; continue }
        if (c == "\"") break
        if (c == "$" && substr(s, k + 1, 1) == "(") k = matchparen(s, k + 1)
      }
      continue
    }
    if (c == "(") d++
    else if (c == ")") { d--; if (d == 0) return k }
  }
  return n + 1
}
function nl(s,   t) { t = s; return gsub(/\n/, "", t) }
function queue(txt, ln) { qn++; QT[qn] = txt; QL[qn] = ln }
# every $( ) and `...` in a heredoc body is executed when the delimiter is unquoted: scan them
function harvest(b, ln,   k, e, c, n) {
  n = length(b)
  for (k = 1; k <= n; k++) {
    c = substr(b, k, 1)
    if (c == "\\") { k++; continue }
    if (c == "$" && substr(b, k + 1, 1) == "(" && substr(b, k + 2, 1) != "(") {
      e = matchparen(b, k + 1); queue(substr(b, k + 2, e - k - 2), ln + nl(substr(b, 1, k))); k = e
    } else if (c == "`") {
      e = index(substr(b, k + 1), "`"); if (e == 0) e = n - k + 1
      queue(substr(b, k + 1, e - 1), ln + nl(substr(b, 1, k))); k += e
    }
  }
}
function bind(name, isexp,   why) {
  if (name ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
    BIND[name] = 1
    why = envbad(name, isexp ? "http.x.extraheader" : "")
    if (why != "") redt("PATH", curln, "read / for / printf -v / unset / export binds " name ": " why)
  }
}
# identifiers on the left of an assignment operator inside (( )) / $(( )) / ${V:=w}
function bindarith(t,   a, k, m) {
  while (match(t, /[A-Za-z_][A-Za-z0-9_]*[ \t]*(\+|-|\*|\/|%|<<|>>|&|\^|\|)?=[^=]/)) {
    m = substr(t, RSTART, RLENGTH); sub(/[^A-Za-z0-9_].*$/, "", m); bind(m); t = substr(t, RSTART + RLENGTH)
  }
}
function record_asg(tok, ln,   nm, pl, val, sub1, pl2) {
  nm = tok; sub(/[+\[=].*$/, "", nm)
  if (tok ~ /^[A-Za-z_][A-Za-z0-9_]*\[/) { bind(nm); return }
  pl = (tok ~ /^[A-Za-z_][A-Za-z0-9_]*\+=/)
  val = tok; sub(/^[A-Za-z_][A-Za-z0-9_]*\+?=/, "", val)
  pl2 = envbad(nm, val)
  if (pl2 != "") redt("PATH", ln, "assignment to " nm ": " pl2 " (a step that changes what a command word means is RED)")
  if (pl) PLUS[nm] = 1
  ASGN[nm]++
  if (ASGN[nm] == 1) { ASGV[nm] = val; ASGS[nm] = ++SEQ }
}
function chkword(w, ln,   v, nm) {
  WORDS++
  v = lit(w)
  if (v != "") return v
  if (w ~ /^"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?$/) {
    nm = w; gsub(/["${}]/, "", nm)
    DN++; DNM[DN] = nm; DLN[DN] = ln; DSQ[DN] = ++SEQ; DW[DN] = w
    return "\002"
  }
  if (index(w, "\003")) red(ln, "command word " shown(w) " is a ${{ }} expression: the scanner cannot see what will run")
  else red(ln, "command word " shown(w) " is not a plain literal word (variable, expansion, quote-concatenation, backslash or glob)")
  return ""
}
function dangerous(b) { return (b == "eval" || b == "alias" || b == "source" || b == "." || b ~ /^(sh|bash|dash|zsh|ksh|ash|trap)$/) }
# resolve the deferred lone-$VAR command words at the end of the step
function resolve_all(   i, nm, v, b) {
  for (i = 1; i <= DN; i++) {
    nm = DNM[i]
    v = ASGV[nm]; sub(/^["']/, "", v); sub(/["']$/, "", v)
    if (ASGN[nm] == 1 && !(nm in PLUS) && !(nm in BIND) && ASGS[nm] < DSQ[i] && lit(ASGV[nm]) != "" && !dangerous(bn(v)) && (bn(v) in SIMPLE)) continue
    red(DLN[i], "command word " shown(DW[i]) " is a variable that is not assigned exactly once, by a plain VAR=literal, before this use, or its literal is not a SIMPLE listed command (+=, a second assignment, read/for/:= binding, env-only, a dangerous literal, or a listed command whose arguments matter)")
  }
  DN = 0
}
# --- ownership primitives at ANY token position of a statement ------------------------------------------------
# Tokens are de-quoted, split on whitespace and shell metacharacters, and each piece is classified by its basename.
# A wrapper, a quoted payload (su -c 'tar --owner=0 ..'), a neighbouring comment or an OWNER_UG mention changes nothing.
function primscan(a, b,   i, w, m, P, parts, np, q, j, base, k, x, V) {
  m = 0
  for (i = a; i <= b; i++) {
    if (RD[i]) continue
    w = TK[i]
    # an ANSI-C quoted word ($'..') holds escapes the scanner does not decode: it could spell any option or command
    if (w ~ /^\$'.*\\[xuU0-7]/) { redt("INTERP", TKL[i], "ANSI-C quoted word with a hex/octal/unicode escape: the scanner does not decode it"); return }
    gsub(/\003X\003/, " EXPR ", w); gsub(/\\[nt]/, " ", w); gsub(/["'\\]/, "", w)
    np = split(w, parts, /[ \t\n;&|(){}<>`$=,]+/)
    for (q = 1; q <= np; q++) if (parts[q] != "") { m++; P[m] = parts[q]; RAWI[m] = i }
    V[i] = (TK[i] ~ /^"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?$/)
  }
  if (m == 0) return
  if (bn(P[1]) ~ /^(echo|printf)$/) return
  for (j = 1; j <= m; j++) {
    base = bn(P[j])
    if (base ~ /^(tar|bsdtar|gtar|pax|cpio)$/) {
      # GNU long options may be abbreviated (--ow=0 is --owner=0); a bare $VAR word could hold any option
      for (k = j + 1; k <= m; k++) if (P[k] ~ /^--(to-command|use-compress-program|checkpoint-action|info-script|new-volume-script|rmt-command|rsh-command)$/ || P[k] ~ /^-[A-Za-z]*[IF]$/) { redt("TARGET", TKL[RAWI[k]], base " " P[k] " runs a command"); return }
      for (k = j + 1; k <= m; k++) if (P[k] ~ /^--(ow|gr|same-o|owner-|group-)[a-z-]*$/ || (base == "cpio" && P[k] ~ /^-[A-Za-z]*p/)) { redt("TARGET", TKL[RAWI[k]], base " " P[k] " sets file ownership"); return }
      # (the word after an option that takes a path -C/-f/-T/-X/--directory/--file is a path, not an option)
      for (i = a + 1; i <= b; i++) if (!RD[i] && V[i] && !(TK[i - 1] ~ /^-[A-Za-z]*[CfTX]$/ || TK[i - 1] ~ /^--(directory|file|files-from|exclude-from|exclude)$/)) { redt("TARGET", TKL[i], base " with a bare variable word " shown(TK[i]) ": it can hold an ownership option"); return }
    } else if (base == "install" && !(j > 1 && bn(P[j - 1]) ~ /^(cargo|npm|yarn|pnpm|go|pip|pip3|apt|apt-get|brew|gem|dnf|yum|apk|rustup|helm|nix|conda|choco|snap|pipx|bundle)$/)) {
      for (k = j + 1; k <= m; k++) if (P[k] ~ /^-[A-Za-z]*[og]/ || P[k] ~ /^--(o|g)[a-z]*$/) { redt("TARGET", TKL[RAWI[k]], "install " P[k] " sets file ownership"); return }
      for (i = a + 1; i <= b; i++) if (!RD[i] && V[i]) { redt("TARGET", TKL[i], "install with a bare variable word " shown(TK[i]) ": it can hold an ownership option"); return }
    } else if (base ~ /^(cp|mv|rsync|scp|ditto)$/) {
      for (k = j + 1; k <= m; k++) if (P[k] ~ /^--(ch|ow|gr|us|same-o|ar|pre)[a-z-]*$/ || (P[k] ~ /^(ownership|all)$/ && P[k - 1] ~ /^--pre/) || (P[k] ~ /^-[A-Za-z]*[aopg][A-Za-z]*$/ && base ~ /^(cp|rsync)$/)) { redt("TARGET", TKL[RAWI[k]], base " " P[k] " can set or preserve file ownership"); return }
    } else if (base ~ /^(setfacl|chacl|setcap)$/) {
      redt("TARGET", TKL[RAWI[j]], base " changes access control on files"); return
    } else if (base == "chmod") {
      for (i = a; i <= b; i++) if (!RD[i]) { x = TK[i]
        if (x ~ /\$|\003|`/ || x ~ /^-[A-Za-z]*R/ || x == "--recursive" || x == "." || x == ".." || x ~ /\*/ || x ~ /(WORK_ROOT|RUNNER_TEMP|GITHUB_WORKSPACE|RUNNER_WORKSPACE|_work|_temp|__w|\/github\/|HOME)/) { redt("TARGET", TKL[i], "chmod aimed at the work tree or at an operand the scanner cannot read"); return }
      }
    }
  }
}
function shellrange(j, b,   k, t, hasc, fed, p, e, ok) {
  fed = 0
  for (k = j + 1; k <= b; k++) if (RD[k] == 1 && TK[k] ~ /^</) fed = 1
  for (k = j + 1; k <= b; k++) {
    if (RD[k]) continue
    t = TK[k]
    if (t ~ /^([-+]o|-O|\+O|--rcfile|--init-file)$/) { k++; continue }
    if (t == "-") { redt("INTERP", TKL[j], "shell reads its script from stdin (-)"); return }
    if (t == "--") {
      k++; while (k <= b && RD[k]) k++
      if (k <= b) redt("INTERP", TKL[j], "shell runs a script file the step may have written"); else redt("INTERP", TKL[j], "shell has no script: it reads stdin")
      return
    }
    if (t ~ /^-[A-Za-z]+$/) {
      if (t ~ /c/) {
        p = k + 1; while (p <= b && RD[p]) p++
        if (p > b) { redt("INTERP", TKL[j], "shell -c without a payload"); return }
        e = unq(TK[p])
        if (e == "\001") red(TKL[j], "shell -c with a payload that is not a literal string")
        else queue(e, TKL[p])
        return
      }
      if (t ~ /s/) { redt("INTERP", TKL[j], "shell -s reads its script from stdin"); return }
      continue
    }
    if (t ~ /^[-+]/) continue
    redt("INTERP", TKL[j], "shell runs a script file or process substitution the step may have written")
    return
  }
  redt("INTERP", TKL[j], fed ? "text fed to a shell by a redirect, heredoc or here-string" : "shell with no -c payload and no script reads stdin (a pipe feeds it)")
}
# --- capability checks for embedded languages (r5) --------------------------------------------------------------
# awk is an interpreter: system(), a pipe to or from a command and a dynamic command string run arbitrary commands
# whatever the spelling ("\143hown", "ch" "own"). Plain text-processing awk stays green. JavaScript bodies (github-script)
# are judged the same way: by what they can reach, never by how a name is spelled.
# deq(w): the text the shell passes for the quoted word w. DQDYN is set when any part of it is an expansion / ${{ }}.
function deq(w,   n, i, c, c2, o, e) {
  n = length(w); o = ""; DQDYN = 0
  for (i = 1; i <= n; i++) {
    c = substr(w, i, 1)
    if (c == "\003" || c == "`") { DQDYN = 1; o = o c; continue }
    if (c == "'") { e = index(substr(w, i + 1), "'"); if (e == 0) { o = o substr(w, i + 1); break } o = o substr(w, i + 1, e - 1); i += e; continue }
    if (c == "\"") {
      for (i++; i <= n; i++) {
        c = substr(w, i, 1)
        if (c == "\"") break
        if (c == "\\") { c2 = substr(w, i + 1, 1); if (c2 == "$" || c2 == "`" || c2 == "\"" || c2 == "\\") { o = o c2; i++; continue } o = o c; continue }
        if (c == "\003" || c == "`") DQDYN = 1
        if (c == "$" && substr(w, i + 1, 1) ~ /[A-Za-z0-9_{(@*#?!$'-]/) DQDYN = 1
        o = o c
      }
      continue
    }
    if (c == "\\") { o = o substr(w, i + 1, 1); i++; continue }
    if (c == "$" && substr(w, i + 1, 1) ~ /[A-Za-z0-9_{(@*#?!$'-]/) DQDYN = 1
    o = o c
  }
  return o
}
# awkbad(t): why the awk program text t can run a command (or cannot be read with certainty), else "".
# Strings and regex literals are blanked first; what is left is code. A slash is a regex only where a division is
# impossible (after an operator, a statement start, a keyword); a slash after ")" is ambiguous and RED.
function awkbad(t,   n, i, c, o, prev, e, body, nb, np, lastw, w) {
  n = length(t); o = ""; prev = "\n"; lastw = ""
  for (i = 1; i <= n; i++) {
    c = substr(t, i, 1)
    if (c ~ /[A-Za-z0-9_]/) { w = ""; for (e = i; e <= n && substr(t, e, 1) ~ /[A-Za-z0-9_]/; e++) w = w substr(t, e, 1); o = o w; lastw = w; prev = "w"; i = e - 1; continue }
    if (c == "\"") {
      for (i++; i <= n; i++) { c = substr(t, i, 1); if (c == "\\") { i++; continue } if (c == "\"") break }
      if (i > n) return "unterminated string"
      o = o "S"; prev = "S"; lastw = ""; continue
    }
    if (c == "#") { e = index(substr(t, i), "\n"); if (e == 0) break; i += e - 2; continue }
    if (c == "\n") { o = o c; prev = "\n"; lastw = ""; continue }
    if (c == " " || c == "\t") { o = o " "; continue }
    if (c == "/") {
      if (prev == ")") return "a slash after a closing parenthesis: division or regex cannot be told apart"
      if (prev == "\n" || (prev == "w" && lastw ~ /^(print|printf|return|else|do|in|getline|exit|case)$/) || (prev != "w" && prev != "S" && prev != "R" && prev != "]" && index("(,~!{};&|=<>?:", prev))) {
        body = ""
        for (i++; i <= n; i++) {
          c = substr(t, i, 1)
          if (c == "\\") { body = body c substr(t, i + 1, 1); i++; continue }
          if (c == "/") break
          if (c == "\n") return "unterminated regex"
          body = body c
        }
        if (i > n) return "unterminated regex"
        nb = gsub(/\[/, "[", body); np = gsub(/\]/, "]", body)
        if (nb > np) return "regex with an unclosed bracket expression (awk implementations end it differently)"
        o = o "R"; prev = "R"; lastw = ""; continue
      }
    }
    o = o c; prev = c; lastw = ""
  }
  if (index(o, "@")) return "@ (gawk indirect call, @load or @include)"
  gsub(/\|\|/, "  ", o)
  if (index(o, "|")) return "a pipe to or from a command (print |, | getline, |&)"
  if (o ~ /(^|[^A-Za-z0-9_])system[ ]*\(/ || o ~ /(^|[^A-Za-z0-9_])system[ ]*$/) return "system()"
  return ""
}
function awkwhy(w,   t) {
  if (index(w, "\003")) return "the program holds a ${{ }} expression"
  t = deq(w)
  if (DQDYN) return "the program is built by shell expansion"
  return awkbad(t)
}
function awkscan(j, b,   k, t, why, got) {
  got = 0
  for (k = j + 1; k <= b; k++) {
    if (RD[k]) continue
    t = TK[k]
    if (t ~ /^-[fEilW]/ || t ~ /^--(file|exec|include|load)/) { redt("INTERP", TKL[j], "awk reads its program from a file or loads an extension: the program is not read by this scanner"); return }
    if (t == "-v" || t == "-F") { k++; continue }
    if (t == "-e" || t == "--source") {
      k++; if (k > b) return
      got = 1; why = awkwhy(TK[k]); if (why != "") { redt("INTERP", TKL[j], "awk program can run a command or is not readable (" why ")"); return }
      continue
    }
    if (t ~ /^--source=/) { got = 1; why = awkwhy(substr(t, 10)); if (why != "") { redt("INTERP", TKL[j], "awk program can run a command or is not readable (" why ")"); return } continue }
    if (t == "--" || t ~ /^-/) continue
    if (!got) { why = awkwhy(t); if (why != "") redt("INTERP", TKL[j], "awk program can run a command or is not readable (" why ")") }
    return
  }
}
# jsbad(t): why the JavaScript body t can run a command or reach an ownership call, else "". Raw text, no masking:
# a quote or a regex literal can never hide code from it. The price is a false RED on a bracket inside a string,
# which the allowlist (exact step + line) is for.
function jsbad(t,   n, i, j, k, c, pc, wd, idx, depth, s, n1, n2, af) {
  if (index(t, "\003") || index(t, "${{")) return "a ${{ }} expression is pasted into the JavaScript source"
  if (t ~ /child_process|@actions\/exec|shelljs|execa|cross-spawn|node-pty/) return "child_process / @actions/exec or another process-spawning module"
  if (t ~ /(^|[^A-Za-z0-9_$])(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork|getExecOutput)([^A-Za-z0-9_$]|$)/) return "exec / spawn / fork"
  if (tolower(t) ~ /chown|chgrp|setfacl|chacl/) return "an ownership call (chown / chgrp / setfacl)"
  if (t ~ /(^|[^A-Za-z0-9_$])(eval|Function|constructor|__proto__|globalThis|global|Reflect|Proxy|vm|__original_require__|arguments)([^A-Za-z0-9_$]|$)/) return "code-from-text or reflection (eval, Function, constructor, __proto__, global, Reflect, Proxy, vm, arguments)"
  if (t ~ /(^|[^A-Za-z0-9_$])import[ \t\n]*\(/) return "dynamic import()"
  if (t ~ /process[ \t\n]*\.[ \t\n]*(binding|dlopen|mainModule|_linkedBinding)/) return "process.binding / dlopen / mainModule"
  if (t ~ /Object[ \t\n]*\.[ \t\n]*(getPrototypeOf|setPrototypeOf|getOwnProperty[A-Za-z]*|values|entries|fromEntries|defineProperty|defineProperties)/) return "Object reflection (it can enumerate fs and call a member by name)"
  if (t ~ /\\[xu0-7]/) return "escape sequence in the source (it can spell any name)"
  s = t; n1 = gsub(/(^|[^A-Za-z0-9_$])require([^A-Za-z0-9_$]|$)/, "&", s)
  s = t; n2 = gsub(/(^|[^A-Za-z0-9_$.])require[ \t]*\([ \t]*('[A-Za-z0-9_@.:\/-]+'|"[A-Za-z0-9_@.:\/-]+")[ \t]*\)/, "&", s)
  if (n1 != n2) return "require() with a non-literal argument, or require used as a value"
  if (t ~ /require[ \t]*\([ \t]*['"](node:)?(module|worker_threads|cluster|repl|inspector|v8|wasi|process)['"]/) return "require of a module that can run or load code"
  n = length(t)
  for (i = 1; i <= n; i++) {
    if (substr(t, i, 1) != "[") continue
    for (j = i - 1; j >= 1 && substr(t, j, 1) ~ /[ \t\n]/; j--) ;
    pc = (j >= 1) ? substr(t, j, 1) : ""
    af = (pc != "" && pc ~ /[])'"`A-Za-z0-9_$]/)
    if (af && pc ~ /[A-Za-z0-9_$]/) { s = substr(t, 1, j); match(s, /[A-Za-z0-9_$]+$/); wd = substr(s, RSTART, RLENGTH); if (wd ~ /^(return|typeof|in|of|case|await|yield|throw|new|delete|void|else|do|instanceof)$/) af = 0 }
    depth = 0; for (k = i; k <= n; k++) { c = substr(t, k, 1); if (c == "[") depth++; else if (c == "]") { depth--; if (depth == 0) break } }
    idx = substr(t, i + 1, k - i - 1)
    if (af && (k > n || idx !~ /^[ \t\n]*-?[0-9]+[ \t\n]*$/)) return "computed property access (obj[expr]) with an index that is not an integer literal"
    if (pc ~ /[{,]/ && k <= n) { for (j = k + 1; j <= n && substr(t, j, 1) ~ /[ \t\n]/; j++) ; if (substr(t, j, 1) == ":") return "computed property key ({[expr]: ...})" }
  }
  return ""
}
# a pipe may feed only a consumer that reads data: anything else could execute the text
function safe_consumer(b) {
  return (b ~ /^(cat|grep|egrep|fgrep|sed|awk|gawk|mawk|cut|tr|sort|uniq|head|tail|tee|wc|jq|read|base64|xxd|od|sha256sum|sha1sum|sha512sum|md5sum|b2sum|gzip|gunzip|zcat|bzip2|xz|zstd|column|paste|join|comm|diff|cmp|fold|nl|rev|less|more|xargs|true|false|test|\[|\[\[|:|curl|wget|gh|docker|cosign|openssl|gpg|git|cargo|rustc|jq|sponge|mapfile|readarray|while|until|printf|echo|date|sleep|logger|cmp|realpath|dirname|basename|stat|ls|find|rm|mkdir|touch|mv|cp|ln|df|du|free|ps|lsof|ss|ip|tput|wall|mail|sendmail|nproc|uname|id|whoami|env|sudo|command|tac|expand|unexpand|split|csplit|shuf|seq|yes|timeout|nice|ionice|time|stdbuf|flock|systemctl|journalctl)$/)
}
# evalrange(a, b): the statement held in TK[a..b] (raw words)
# sed is an interpreter too: the e command and the s///e flag run a shell command. sedbad(t): why the sed script text t
# can run a command (or cannot be parsed with certainty), else "". Fail closed: an unknown command letter, an
# unterminated pattern and a script from a file (-f) are all RED. --sandbox makes e/w/r impossible and is green.
function sed_skipdelim(t, p, d,   n, c) {
  n = length(t)
  for (; p <= n; p++) {
    c = substr(t, p, 1)
    if (c == "\\") { p++; continue }
    if (c == "[") { p++; if (substr(t, p, 1) == "^") p++; if (substr(t, p, 1) == "]") p++; while (p <= n && substr(t, p, 1) != "]") p++; continue }
    if (c == d) return p
  }
  return 0
}
function sedbad(t,   n, p, c, d, q, f) {
  n = length(t); p = 1
  while (p <= n) {
    c = substr(t, p, 1)
    if (c ~ /[ \t\n;{}]/) { p++; continue }
    while (1) {
      c = substr(t, p, 1)
      if (c ~ /[0-9$ \t,~+!]/) { p++; continue }
      if (c == "/" || (c == "\\" && p < n)) {
        d = "/"; if (c == "\\") { p++; d = substr(t, p, 1) }
        q = sed_skipdelim(t, p + 1, d); if (q == 0) return "unterminated address regex"
        p = q + 1; while (substr(t, p, 1) ~ /[IM]/) p++
        continue
      }
      break
    }
    c = substr(t, p, 1)
    if (c == "") break
    if (c == "{" || c == "}") { p++; continue }
    if (c == "e") return "the e command runs a shell command"
    if (c == "s") {
      d = substr(t, p + 1, 1); if (d == "" || d == "\n" || d == "\\") return "s with no usable delimiter"
      q = sed_skipdelim(t, p + 2, d); if (q == 0) return "unterminated s pattern"
      q = sed_skipdelim(t, q + 1, d); if (q == 0) return "unterminated s replacement"
      p = q + 1
      while (p <= n && substr(t, p, 1) !~ /[;}\n# \t]/) {
        f = substr(t, p, 1)
        if (f == "e") return "the s///e flag runs the pattern space as a shell command"
        if (f == "w") { q = index(substr(t, p), "\n"); p = (q == 0) ? n + 1 : p + q - 1; break }
        p++
      }
      continue
    }
    if (c == "y") {
      d = substr(t, p + 1, 1); if (d == "" || d == "\n" || d == "\\") return "y with no usable delimiter"
      q = sed_skipdelim(t, p + 2, d); if (q == 0) return "unterminated y"
      q = sed_skipdelim(t, q + 1, d); if (q == 0) return "unterminated y"
      p = q + 1; continue
    }
    if (c ~ /[aic]/) { while (p <= n) { q = index(substr(t, p), "\n"); if (q == 0) { p = n + 1; break } p += q; if (substr(t, p - 2, 1) != "\\") break } continue }
    if (c ~ /[rRwW:#]/) { q = index(substr(t, p), "\n"); p = (q == 0) ? n + 1 : p + q; continue }
    if (c ~ /[bBtT]/) { p++; while (p <= n && substr(t, p, 1) !~ /[;}\n]/) p++; continue }
    if (c ~ /[=dDgGhHlnNpPqQxzF]/) { p++; while (substr(t, p, 1) ~ /[0-9 \t]/) p++; continue }
    return "unknown sed command letter " c
  }
  return ""
}
function sedwhy(w,   t) {
  if (index(w, "\003")) return "the script holds a ${{ }} expression"
  t = deq(w)
  if (DQDYN) return "the script is built by shell expansion"
  return sedbad(t)
}
function sedscan(j, b,   k, t, why, got) {
  got = 0
  for (k = j + 1; k <= b; k++) if (!RD[k] && TK[k] == "--sandbox") return
  for (k = j + 1; k <= b; k++) {
    if (RD[k]) continue
    t = TK[k]
    if (t ~ /^-[A-Za-z]*f/ || t ~ /^--file/) { redt("INTERP", TKL[j], "sed reads its script from a file: the script is not read by this scanner"); return }
    if (t == "-e" || t == "--expression" || (t ~ /^-[A-Za-z]+$/ && t ~ /e$/ && t !~ /^-i/)) {
      k++; if (k > b) return
      got = 1; why = sedwhy(TK[k]); if (why != "") { redt("INTERP", TKL[j], "sed script can run a command or is not readable (" why ")"); return }
      continue
    }
    if (t ~ /^--expression=/) { got = 1; why = sedwhy(substr(t, 14)); if (why != "") { redt("INTERP", TKL[j], "sed script can run a command or is not readable (" why ")"); return } continue }
    if (t == "--" || t ~ /^-/) continue
    if (!got) { why = sedwhy(t); if (why != "") redt("INTERP", TKL[j], "sed script can run a command or is not readable (" why ")") }
    return
  }
}
# make-like tools run recipes, scripts and hooks that live in the repo and are not read here: RED by capability.
# buildtool(bt, j, b): the tool's name when it is a recipe runner, else "".
function buildtool(bt, j, b,   k, s) {
  if (bt ~ /^(make|gmake|bmake|remake|just|ninja|samu|scons|rake|bazel|bazelisk|gradle|gradlew|mvn|mvnw|ant|task|xtask|invoke|tox|nox|meson|cmake|npm|npx|yarn|pnpm|bun|bunx|pnpx|corepack|mage|earthly|doit|waf|buck|buck2|pants|nx|turbo|lerna|grunt|gulp|fab|cargo-xtask|cargo-make|cargo-script)$/) return bt
  if (bt == "cargo") {
    for (k = j + 1; k <= b; k++) {
      s = TK[k]; if (RD[k] || s ~ /^-/ || s ~ /^\+/) continue
      s = lit(s)
      if (s == "") return "cargo <dynamic subcommand>"
      if (s ~ /^(xtask|run|make|script|r)$/) return "cargo " s
      return ""
    }
  }
  return ""
}
# --- ALLOWLIST OF COMMAND WORDS (PMAT-2359, cop ruling: stop denylisting) ------------------------------------------
# Every command word of a run step (the first word of each simple command, and every word after a known wrapper: env,
# sudo, doas, timeout, nice, ionice, command, exec, nohup, setsid, time, busybox, rustup run, xargs, find -exec) must be a
# name on the committed list below, else RED [UNLISTED]. Anything nobody thought of (docker, ssh, nsenter, flock, fakeroot,
# parallel, chronic, stdbuf, a name made by a PATH shim or a git alias) is RED by default; it needs an allowlist row.
# Words are resolved BY NAME: the guard assumes the runner image's binaries are what their names say. An image, or a PATH,
# outside the step is out of claim. Inside the step, these are RED: a PATH change (PATH=, export PATH, env PATH=, a write to
# GITHUB_PATH / GITHUB_ENV / BASH_ENV, read/for/printf -v on PATH), an exec-hook variable (LD_PRELOAD, RUSTC_WRAPPER,
# GIT_SSH_COMMAND, PAGER, GIT_CONFIG_KEY_n with an alias or a program key, ...), a function or alias definition, a git -c,
# a git subcommand off the read list (that is also how a git alias is caught), a git config write, and a write into a
# system directory (a copy of a tool placed under a listed name).
# Two lists: SIMPLE words are readers with no argument that matters, and are the only words a deferred $VAR may stand for;
# the rest are listed but their arguments are read by the branch that owns them (git, gh, cargo, apt-get, sccache, rustup,
# curl, find, xargs, sh, bash, awk, sed, and the writers cp mv rm mkdir touch tee chmod tar chown).
function initlists(   n, a, i) {
  n = split("echo printf test [ [[ ]] : true false exit return break continue shift wait pwd cat grep egrep fgrep head tail cut tr sort uniq wc ls stat id date jq dirname basename realpath readlink mktemp sleep which base64 sha256sum sha1sum md5sum uname nproc hostname whoami df du diff cmp seq xxd od pmat bashrs yamllint cosign openssl rustfmt", a, " ")
  for (i = 1; i <= n; i++) { SIMPLE[a[i]] = 1; LST[a[i]] = 1 }
  n = split("cd set export local readonly declare typeset read unset trap mapfile readarray getopts git gh cargo apt-get sccache rustup curl find xargs sh bash awk sed cp mv rm mkdir touch tee chmod tar chown", a, " ")
  for (i = 1; i <= n; i++) LST[a[i]] = 1
  n = split("cp mv rm mkdir touch tee chmod tar curl sed chown", a, " ")
  for (i = 1; i <= n; i++) WRITER[a[i]] = 1
  n = split("clone fetch rev-parse rev-list merge-base log diff show status cat-file ls-files ls-remote grep describe config", a, " ")
  for (i = 1; i <= n; i++) GITOK[a[i]] = 1
  n = split("build test fmt clippy check nextest deny audit llvm-cov bench metadata install doc tree fetch version", a, " ")
  for (i = 1; i <= n; i++) CARGOOK[a[i]] = 1
}
# envbad(nm, val): why assigning the variable nm (value text val, "" when unknown) lets a step change what a later command word means
function envbad(nm, val,   v) {
  if (nm == "PATH") return "PATH"
  if (nm ~ /^(BASH_ENV|ENV|CDPATH|SHELLOPTS|BASHOPTS|PROMPT_COMMAND|PS4|BASH_FUNC_.*|LD_[A-Z_]+|NODE_OPTIONS|PERL5OPT|PERL5LIB|PYTHONSTARTUP|PYTHONPATH|RUBYOPT|RUBYLIB|AWKPATH|AWKLIBPATH|SHELL|PAGER|EDITOR|VISUAL|SSH_ASKPASS|HOME|XDG_CONFIG_HOME|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTDOC|CARGO_BUILD_RUSTC.*|CARGO_BUILD_RUSTDOC.*|CARGO_ALIAS_.*|CARGO_TARGET_.*|GIT_(SSH|SSH_COMMAND|EXEC_PATH|EXTERNAL_DIFF|PAGER|EDITOR|SEQUENCE_EDITOR|ASKPASS|PROXY_COMMAND|TEMPLATE_DIR|CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_PARAMETERS|CONFIG|DIR|WORK_TREE))$/) return "an exec-hook / config-redirect variable"
  if (nm ~ /^GIT_CONFIG_KEY_[0-9]+$/ && val != "http.x.extraheader") {
    v = val; gsub(/^["']|["']$/, "", v)
    if (v !~ /^http\.[A-Za-z0-9_.:\/-]*\.extraheader$/ && v !~ /^safe\.directory$/ && v !~ /^user\.(name|email)$/ && v !~ /^url\.[A-Za-z0-9_.:\/@-]+\.insteadof$/) return "a GIT_CONFIG_KEY that is not a known data key (an alias or a program key)"
  }
  return ""
}
# sysdir(w): the word w names a path inside a system directory (a place a tool of a listed name lives)
function sysdir(w,   x, nm, v) {
  x = w; gsub(/["']/, "", x); sub(/^[A-Za-z0-9_-]+=/, "", x)
  if (x ~ /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/) {
    nm = x; sub(/^\$\{?/, "", nm); sub(/[^A-Za-z0-9_].*$/, "", nm)
    if (ASGN[nm] == 1 && !(nm in PLUS) && !(nm in BIND) && lit(ASGV[nm]) != "") { v = ASGV[nm]; gsub(/["']/, "", v); sub(/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/, v, x) }
  }
  return (x ~ /^\/(usr|bin|sbin|lib|lib32|lib64|opt|etc|boot|snap|var\/lib)(\/|$)/)
}
# a statement that touches the file-command files or writes into a system directory
function envkeyok(a, b,   k, x, nm) {
  for (k = a + 1; k <= b; k++) { if (RD[k]) continue; if (TK[k] ~ /^-[neE]+$/) { if (TK[k] ~ /e/) return 0; continue } break }
  if (k > b) return 0
  x = TK[k]; gsub(/^["']|["']$/, "", x)
  if (x ~ /\\n|\\r|\n|\003/) return 0
  if (x !~ /^[A-Za-z_][A-Za-z0-9_]*=/) return 0
  nm = x; sub(/=.*$/, "", nm)
  return (envbad(nm, "") == "")
}
function envfilescan(a, b,   i, s, c) {
  c = lit(TK[a]); s = bn(c)
  for (i = a; i <= b; i++) {
    if (RD[i] == 2 && TK[i - 1] ~ />/ && sysdir(TK[i])) { redt("SYSDIR", TKL[i], "redirect into a system directory: it can place a tool under a listed name"); return }
    if (TK[i] ~ /GITHUB_PATH|BASH_ENV/) { redt("PATH", TKL[i], "a word names GITHUB_PATH / BASH_ENV: it changes the PATH or the shell start-up of later steps"); return }
    if (TK[i] ~ /GITHUB_ENV/) {
      if (s == "stat" || TK[i] ~ /^[A-Za-z_][A-Za-z0-9_]*="\$\(stat -c '[^']*' "\$\{GITHUB_(ENV|OUTPUT):-\}"\)"$/) continue
      if ((s == "echo" || s == "printf") && RD[i] == 0) continue
      if (s == "echo" && RD[i] == 2 && TK[i - 1] == ">>" && envkeyok(a, b)) continue
      redt("PATH", TKL[i], "a write to GITHUB_ENV that is not `echo NAME=value` with a plain name: it can set PATH, BASH_ENV or an exec hook for later steps"); return
    }
  }
}
function wrscan(j, b, base,   k) {
  for (k = j + 1; k <= b; k++) if (!RD[k] && sysdir(TK[k])) { redt("SYSDIR", TKL[k], base " operand in a system directory: it can place or alter a tool under a listed name"); return 1 }
  return 0
}
function gitscan(j, b,   k, t, s, rf, wf, n) {
  k = j + 1
  while (k <= b) {
    if (RD[k]) { k++; continue }
    t = TK[k]
    if (t == "-C" || t == "--git-dir" || t == "--work-tree" || t == "--namespace") { k += 2; continue }
    if (t ~ /^(-p|--no-pager|--paginate|--no-optional-locks|--bare|--literal-pathspecs|--no-replace-objects)$/ || t ~ /^--(git-dir|work-tree|namespace)=/) { k++; continue }
    if (t ~ /^-c/ || t ~ /^--config-env/ || t ~ /^--exec-path/ || t == "--super-prefix") { redt("GITCFG", TKL[j], "git " t " sets configuration (an alias or a program key) for this command"); return }
    if (t ~ /^-/) { redt("UNLISTED", TKL[j], "git global option " t " is not on the known list"); return }
    break
  }
  if (k > b) return
  s = lit(TK[k])
  if (s == "") { redt("UNLISTED", TKL[j], "git subcommand is not a plain literal word (an alias can hide behind it)"); return }
  if (!(s in GITOK)) { redt("UNLISTED", TKL[j], "git subcommand " s " is not on the read list (a git alias or an external git-" s " would run)"); return }
  for (n = k + 1; n <= b; n++) if (!RD[n] && TK[n] ~ /^(-c|--config|--config-env|--upload-pack|-u|--receive-pack|--exec|--template|--ext-diff|--textconv|-O|--open-files-in-pager|--run)(=|$)/) { redt("GITCFG", TKL[j], "git " s " " TK[n] " runs a program or sets configuration"); return }
  if (s == "config") {
    rf = 0; wf = 0
    for (n = k + 1; n <= b; n++) if (!RD[n]) {
      if (TK[n] ~ /^(--get|--get-all|--get-regexp|--get-urlmatch|--list|-l|--get-color|--get-colorbool|--show-origin|--show-scope|--name-only|--null|-z|--global|--system|--local|--worktree|--file|-f|--includes|--no-includes|--type=.*|--bool|--int|--path)$/) { if (TK[n] ~ /^(--get|--get-all|--get-regexp|--get-urlmatch|--list|-l)$/) rf = 1; if (TK[n] ~ /^(--file|-f)$/) n++; continue }
      if (TK[n] ~ /^-/) { wf = 1; continue }
    }
    if (!rf || wf) redt("GITCFG", TKL[j], "git config that is not a read (--get / --get-all / --list): a config write can define an alias or a program key")
    else {
      # a read form still has exactly one key operand at most; any extra operand is a value, which makes it a write
      rf = 0; for (n = k + 1; n <= b; n++) if (!RD[n] && TK[n] !~ /^-/ && TK[n - 1] !~ /^(--file|-f)$/) rf++
      if (rf > 1) redt("GITCFG", TKL[j], "git config with a key and a value is a write")
    }
  }
}
function ghscan(j, b,   k, t, g, v, pair, n) {
  k = j + 1; while (k <= b && RD[k]) k++
  if (k > b) return
  t = TK[k]
  if (t ~ /^-/) { if (t ~ /^(--version|--help|-h)$/) return; redt("UNLISTED", TKL[j], "gh option " t " before the subcommand: group and verb cannot be read"); return }
  g = lit(t); v = ""
  for (n = k + 1; n <= b; n++) if (!RD[n] && TK[n] !~ /^-/) { v = lit(TK[n]); break }
  if (g == "") { redt("UNLISTED", TKL[j], "gh subcommand is not a plain literal word"); return }
  if (g == "api") {
    for (n = k + 1; n <= b; n++) if (!RD[n]) {
      t = TK[n]
      if (t ~ /^(-f|-F|--field|--raw-field|--input)/ || t ~ /^-[A-Za-z]*[fF]$/) { redt("GHWRITE", TKL[j], "gh api with a field or input body is a POST"); return }
      if (t ~ /^(-X|--method)$/) { if (toupper(unq(TK[n + 1])) != "GET" && toupper(lit(TK[n + 1])) != "GET") { redt("GHWRITE", TKL[j], "gh api with a method other than GET"); return } n++; continue }
      if (t ~ /^-X./ || t ~ /^--method=/) { redt("GHWRITE", TKL[j], "gh api with a method option the scanner does not read"); return }
    }
    return
  }
  pair = g " " v
  if (pair ~ /^(pr (view|list|diff|checks|status)|run (view|list)|repo view|release (view|list|download)|issue (view|list|status)|auth status)$/) return
  redt("GHWRITE", TKL[j], "gh " pair " is not on the read list: it can write, merge, upload, or run an alias or an extension")
}
function cargoscan(j, b,   k, s, n) {
  k = j + 1; while (k <= b && (RD[k] || TK[k] ~ /^\+/)) k++
  if (k > b) return
  s = lit(TK[k])
  if (s == "") { redt("UNLISTED", TKL[j], "cargo subcommand is not a plain literal word"); return }
  if (s ~ /^(--version|-V|-vV|--list)$/) return
  if (!(s in CARGOOK)) { redt("UNLISTED", TKL[j], "cargo subcommand " s " is not on the list (an alias or an external cargo-" s " would run)"); return }
  for (n = j + 1; n <= b; n++) if (!RD[n] && TK[n] ~ /^(--config|-Z|--config=.*)/) { redt("GITCFG", TKL[j], "cargo " TK[n] " sets configuration (an alias, a linker or a wrapper) for this command"); return }
}
function aptscan(j, b,   k, s, n) {
  k = j + 1; while (k <= b && (RD[k] || TK[k] ~ /^-[yqfV]+$/ || TK[k] == "--no-install-recommends")) k++
  if (k > b) return
  s = lit(TK[k])
  if (s !~ /^(update|install|clean|autoremove)$/) { redt("UNLISTED", TKL[j], "apt-get " shown(TK[k]) " is not update / install / clean / autoremove"); return }
  for (n = j + 1; n <= b; n++) if (!RD[n] && TK[n] ~ /^(-o|--option|-c|--config-file|-oAPT.*)/) { redt("GITCFG", TKL[j], "apt-get " TK[n] " runs a hook command"); return }
}
function sccachescan(j, b,   k, s) {
  k = j + 1; while (k <= b && RD[k]) k++
  if (k > b) return
  s = lit(TK[k])
  if (s !~ /^(--show-stats|--start-server|--stop-server|--zero-stats|--version|-s|-z|-V)$/) redt("UNLISTED", TKL[j], "sccache " shown(TK[k]) ": sccache followed by anything else wraps and runs that command as a compiler")
}
function rustupscan(j, b,   k, s) {
  k = j + 1; while (k <= b && RD[k]) k++
  if (k > b) return
  s = lit(TK[k])
  if (s !~ /^(show|toolchain|component|target|update|default|which|--version|-V)$/) redt("UNLISTED", TKL[j], "rustup " shown(TK[k]) " is not on the list (rustup run is read as a wrapper)")
}
function curlscan(j, b,   k) {
  for (k = j + 1; k <= b; k++) if (!RD[k] && TK[k] ~ /^(-K|--config|-K.+)$/) { redt("GITCFG", TKL[j], "curl " TK[k] " reads options (an exec-capable config) from a file"); return }
}
function evalrange(a, b, depth,   j, t, bt, w, v, k, e, p, pl, sc, ex, s2) {
  j = a
  while (j <= b) {
    if (RD[j]) { j++; continue }
    t = lit(TK[j]); bt = bn(t)
    if (t ~ /^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=/ || TK[j] ~ /^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=/) { record_asg(TK[j], TKL[j]); j++; continue }
    if (bt ~ /^(do|then|else|elif|if|while|until|time|!|nohup|setsid|builtin|\{|\}|done|fi|esac)$/) { j++; continue }
    if (bt == "sudo" || bt == "doas") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[ughCDprtTU]$/) j++; j++ } continue }
    if (bt == "command") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[vV]$/) return; j++ } continue }
    if (bt == "exec") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] == "-a") j++; j++ } continue }
    if (bt == "busybox") { j++; continue }
    if (bt == "rustup" && lit(TK[j + 1]) == "run") { j += 3; continue }
    if (bt ~ /^(su|runuser)$/) {
      for (k = j + 1; k <= b; k++) if (!RD[k] && (TK[k] ~ /^-[A-Za-z]*c$/ || TK[k] == "--command")) {
        e = (k + 1 <= b) ? unq(TK[k + 1]) : "\001"
        if (e == "\001") redt("INTERP", TKL[j], bt " -c with a payload that is not a literal string"); else queue(e, TKL[k + 1])
        return
      }
      redt("INTERP", TKL[j], bt " without a literal -c payload runs a shell the scanner does not read"); return
    }
    if (bt == "env") { j++; while (j <= b && (TK[j] ~ /^-/ || TK[j] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) { if (TK[j] ~ /^(-[A-Za-z]*S|--split-string)/) { redt("INTERP", TKL[j], "env -S splits and runs a string the scanner does not read"); return } if (TK[j] ~ /=/ && TK[j] !~ /^-/) record_asg(TK[j], TKL[j]); j++ } continue }
    if (bt == "nice") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] == "-n") j++; j++ } continue }
    if (bt == "ionice") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[ctnp]$/) j++; j++ } continue }
    if (bt == "timeout") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[ks]$/) j++; j++ } if (j <= b && TK[j] ~ /^[0-9.]+[smhd]?$/) j++; continue }
    if (bt == "xargs") { j++; PIPED = 0; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^(-[A-Za-z]*[IiJ]|--replace|-J)/) XREPL = 1; if (TK[j] ~ /^-[nIPLsEda]$/ || TK[j] ~ /^--(max-args|max-procs|replace|delimiter|arg-file|max-lines|max-chars|eof)$/) j++; j++ } continue }
    break
  }
  if (j > b) return
  if (lit(TK[j]) == "for" || lit(TK[j]) == "select") { bind(lit(TK[j + 1])); return }
  if (lit(TK[j]) == "function") {
    red(TKL[j], "function definition " shown(TK[j + 1]) " (it can shadow a command by name)"); return
  }
  w = chkword(TK[j], TKL[j])
  if (w == "") return
  if (w == "\002") return
  bt = bn(w)
  # a command word that is a path: a relative one runs a file the step may have written; an absolute one must be a system directory
  if (w ~ /\// && w !~ /^\/(usr|bin|sbin|opt|lib|lib64|etc)\//) { redt("INTERP", TKL[j], "command word " w " is a path outside the system directories: it can be a file the step wrote"); return }
  if (w ~ /\/\.\.?(\/|$)/) { redt("INTERP", TKL[j], "command word " w " has a . or .. path segment: it can reach a file outside the system directories under a system name"); return }
  if (XREPL && (bt ~ /^(sh|bash|dash|zsh|ksh|ash|eval)$/)) { redt("INTERP", TKL[j], "xargs replacement string fed into a shell or eval"); return }
  if (PIPED && !safe_consumer(bt) && bt !~ /^(sh|bash|dash|zsh|ksh|ash|eval)$/) { redt("INTERP", TKL[j], "piped text reaches " bt ", which is not a known data consumer (it may execute it)"); return }
  for (k = a; k <= b; k++) if (RD[k] == 1 && TK[k] ~ /^<<[<-]?$/ && !safe_consumer(bt) && bt !~ /^(sh|bash|dash|zsh|ksh|ash|eval)$/) { redt("INTERP", TKL[j], "a heredoc or here-string feeds text to " bt ", which is not a known data consumer (it may execute it)"); return }
  if (bt == "eval") { redt("INTERP", TKL[j], "eval runs text the scanner cannot read"); return }
  if (bt == "alias") { red(TKL[j], "alias redefines a command word"); return }
  if (bt == "source" || bt == ".") { redt("INTERP", TKL[j], bt " runs a file the scanner does not read"); return }
  if (bt ~ /^(sh|bash|dash|zsh|ksh|ash)$/) { shellrange(j, b); return }
  if (bt ~ /^(awk|gawk|mawk|nawk|original-awk)$/) { awkscan(j, b); return }
  if (bt ~ /^(sed|gsed|busybox-sed)$/) { sedscan(j, b); return }
  if ((e = buildtool(bt, j, b)) != "") { redt("INTERP", TKL[j], e " runs recipes or scripts that live in the repo: the code it runs is not read by this scanner (capability rule)"); return }
  if (bt ~ /^(python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|node|nodejs|php[0-9.]*|pwsh|lua[0-9.]*|luajit|deno|bun|tclsh[0-9.]*|wish|osascript|expect|irb|jshell|Rscript|julia|swift|groovy|escript|guile|racket|ocaml|runghc|ghci|npx|ts-node|tsx)$/) { redt("INTERP", TKL[j], bt " is an interpreter: the program it runs is not read by this scanner"); return }
  if (bt ~ /^(nsenter|chroot|flock|script|watch|parallel|stdbuf|taskset|docker|podman|ssh|unshare|setpriv|capsh|sg|newgrp|sshpass|kubectl|lxc|systemd-run|firejail|bwrap)$/) {
    for (k = j + 1; k <= b; k++) if (!RD[k] && bn(lit(TK[k])) ~ /^(sh|bash|dash|zsh|ksh|ash|eval|su|runuser)$/) { evalrange(k, b, depth + 1); return }
    if (PIPED && bt ~ /^(nsenter|chroot|script|ssh|unshare|setpriv|capsh|sg|newgrp|sshpass|kubectl|lxc|systemd-run|firejail|bwrap)$/) redt("INTERP", TKL[j], "piped text reaches " bt ", which can run it as a command on the other side")
    # fall through: a wrapper that is not on the list is UNLISTED below (r7: the old return let docker, flock, ssh, nsenter pass)
  }
  # r7 ALLOWLIST: every command word must be on the committed list; the branches below read the arguments of the listed words
  if (!(bt in LST)) { redt("UNLISTED", TKL[j], "command word " bt " is not on the committed list of known-safe commands (resolved by name; an image or PATH outside the step is out of claim)"); return }
  if (bt in WRITER) { if (wrscan(j, b, bt)) return }
  if (bt == "git") { gitscan(j, b); return }
  if (bt == "gh") { ghscan(j, b); return }
  if (bt == "cargo") { cargoscan(j, b); return }
  if (bt == "apt-get") { aptscan(j, b); return }
  if (bt == "sccache") { sccachescan(j, b); return }
  if (bt == "rustup") { rustupscan(j, b); return }
  if (bt == "curl") { curlscan(j, b) }
  if (bt == "trap") {
    k = j + 1; while (k <= b && (RD[k] || TK[k] ~ /^-/)) k++
    if (k <= b) {
      e = unq(TK[k])
      if (e != "\001") { if (e != "") queue(e, TKL[k]) }
      else if (lit(TK[k]) == "") red(TKL[j], "trap with a handler that is not a literal string")
    }
    return
  }
  if (bt ~ /^(export|local|readonly|declare|typeset)$/) {
    for (k = j + 1; k <= b; k++) if (!RD[k] && TK[k] ~ /^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=/) record_asg(TK[k], TKL[k]); else if (!RD[k] && TK[k] !~ /^-/) { if (lit(TK[k]) == "") redt("PATH", TKL[k], bt " of a name the scanner cannot read: it can set PATH or an exec-hook variable"); else bind(lit(TK[k]), 1) }
    for (k = j + 1; k <= b; k++) if (TK[k] ~ /^-[A-Za-z]*n/) bind(lit(TK[k + 1]))
    return
  }
  if (bt ~ /^(read|mapfile|readarray|getopts|unset)$/) { for (k = j + 1; k <= b; k++) if (!RD[k] && TK[k] !~ /^-/) { if (lit(TK[k]) == "" && TK[k] !~ /^<|^[0-9]/) redt("PATH", TKL[k], bt " into a name the scanner cannot read: it can set PATH or an exec-hook variable"); else bind(lit(TK[k])) } return }
  if (bt == "printf") { for (k = j + 1; k < b; k++) if (TK[k] == "-v") bind(lit(TK[k + 1])); return }
  if (bt == "find") {
    for (k = j + 1; k <= b; k++) if (TK[k] ~ /^-(exec|execdir|ok|okdir)$/) {
      for (e = k + 1; e <= b && TK[e] != "\134;" && TK[e] != "+" && TK[e] != ";"; e++) ;
      if (e > k + 1) evalrange(k + 1, e - 1, depth + 1)
    }
    return
  }
}
function endstmt(   k) {
  if (TKn > 0 && !patpos) { SEQ++; PIPED = PIPEIN; PIPEIN = 0; XREPL = 0; primscan(1, TKn); envfilescan(1, TKn); evalrange(1, TKn, 0) }
  TKn = 0
  for (k in HDST) if (HDST[k] == SID) HDSH[k] = ((lit(TK[1]) ~ /^(sh|bash|dash|zsh|ksh|ash)$/) ? 1 : 0)
  SID++
}
function pushtok(w, rd) { TKn++; TK[TKn] = w; TKL[TKn] = curln; RD[TKn] = rd }
# a finished word: handle case/dbl-bracket bookkeeping, then push it as a token
function endword(   rd) {
  if (!inW) return
  inW = 0
  if (needt) {
    needt = 0
    if (hdnext) {
      hdnext = 0
      hn++; HDD[hn] = W; HDQ[hn] = (W ~ /['"\\]/); gsub(/['"\\]/, "", HDD[hn]); HDT[hn] = hdtab; HDST[hn] = SID; HDL[hn] = curln
    }
    pushtok(W, 2); W = ""; return
  }
  if (TKn == 0 && W == "esac") { casedepth--; patpos = 0; W = ""; return }
  if (W == "[[" && dbl == 0) dbl = 1
  else if (W == "]]") dbl = 0
  if (W == "in" && TKn == 2 && TK[1] == "case") { TKn = 0; patpos = 1; casedepth++; W = ""; return }
  pushtok(W, 0); W = ""
}
function lexone(s, ln,   isp, n, i, c, c2, e, q, k, op, body, line2, dl, cut, stripped, hs) {
  n = length(s); i = 1; W = ""; inW = 0; TKn = 0; patpos = 0; dbl = 0; casedepth = 0; needt = 0; hdnext = 0; curln = ln; hn = 0
  delete HDST; delete HDSH; PIPEIN = 0
  while (i <= n) {
    c = substr(s, i, 1)
    if (c == " " || c == "\t") { endword(); i++; continue }
    if (c == "\n") {
      endword(); endstmt(); curln++; i++
      # heredoc bodies start on the next line
      for (k = 1; k <= hn; k++) {
        body = ""; line2 = curln
        while (i <= n) {
          e = index(substr(s, i), "\n"); if (e == 0) { dl = substr(s, i); e = n - i + 2 } else dl = substr(s, i, e - 1)
          i += e; curln++
          stripped = dl; if (HDT[k]) sub(/^\t+/, "", stripped)
          if (stripped == HDD[k]) break
          body = body dl "\n"
        }
        if (HDSH[k]) queue(body, line2)
        else if (!HDQ[k]) harvest(body, line2)
      }
      hn = 0; delete HDST
      continue
    }
    if (c == "\\") {
      if (substr(s, i + 1, 1) == "\n") { endword(); i += 2; curln++; continue }
      W = W c substr(s, i + 1, 1); inW = 1; i += 2; continue
    }
    if (c == "#" && !inW) { e = index(substr(s, i), "\n"); if (e == 0) break; i += e - 1; continue }
    if (c == "'") {
      e = index(substr(s, i + 1), "'"); if (e == 0) e = n - i + 1
      W = W substr(s, i, e + 1); curln += nl(substr(s, i, e + 1)); inW = 1; i += e + 1; continue
    }
    if (c == "\"") {
      k = i + 1
      while (k <= n) {
        c2 = substr(s, k, 1)
        if (c2 == "\\") { k += 2; continue }
        if (c2 == "\"") break
        if (c2 == "$" && substr(s, k + 1, 1) == "(") {
          e = matchparen(s, k + 1)
          if (substr(s, k + 2, 1) != "(") queue(substr(s, k + 2, e - k - 2), curln + nl(substr(s, i, k - i)))
          else bindarith(substr(s, k, e - k + 1))
          k = e + 1; continue
        }
        if (c2 == "`") { e = index(substr(s, k + 1), "`"); if (e == 0) e = n - k; queue(substr(s, k + 1, e - 1), curln + nl(substr(s, i, k - i))); k += e + 1; continue }
        if (c2 == "$" && substr(s, k + 1, 1) == "{") { e = index(substr(s, k), "}"); if (e > 0 && substr(s, k, e) ~ /^\$\{[A-Za-z_][A-Za-z0-9_]*:?=/) { hs = substr(s, k + 2, e - 2); sub(/[:=].*$/, "", hs); bind(hs) } }
        k++
      }
      if (k > n) k = n
      W = W substr(s, i, k - i + 1); curln += nl(substr(s, i, k - i + 1)); inW = 1; i = k + 1; continue
    }
    if (c == "`") {
      e = index(substr(s, i + 1), "`"); if (e == 0) e = n - i
      queue(substr(s, i + 1, e - 1), curln); W = W substr(s, i, e + 1); curln += nl(substr(s, i, e + 1)); inW = 1; i += e + 1; continue
    }
    if (c == "$") {
      c2 = substr(s, i + 1, 1)
      if (c2 == "(") {
        e = matchparen(s, i + 1)
        if (substr(s, i + 2, 1) == "(") bindarith(substr(s, i, e - i + 1))
        else queue(substr(s, i + 2, e - i - 2), curln)
        W = W substr(s, i, e - i + 1); curln += nl(substr(s, i, e - i + 1)); inW = 1; i = e + 1; continue
      }
      if (c2 == "{") {
        e = index(substr(s, i), "}"); if (e == 0) e = n - i + 1
        hs = substr(s, i + 2, e - 2); if (hs ~ /^[A-Za-z_][A-Za-z0-9_]*:?=/) { sub(/[:=].*$/, "", hs); bind(hs) }
        W = W substr(s, i, e); inW = 1; i += e; continue
      }
      W = W c; inW = 1; i++; continue
    }
    if (dbl) { W = W c; inW = 1; i++; continue }
    if ((c == "<" || c == ">") && substr(s, i + 1, 1) == "(") {
      e = matchparen(s, i + 1); queue(substr(s, i + 2, e - i - 2), curln)
      W = W substr(s, i, e - i + 1); curln += nl(substr(s, i, e - i + 1)); inW = 1; i = e + 1; continue
    }
    if (c == "(" && inW && W ~ /=$/) { e = matchparen(s, i); W = W substr(s, i, e - i + 1); curln += nl(substr(s, i, e - i + 1)); i = e + 1; continue }
    if (c == "(" && substr(s, i + 1, 1) == "(" && !inW) { e = matchparen(s, i); bindarith(substr(s, i, e - i + 1)); curln += nl(substr(s, i, e - i + 1)); i = e + 1; endstmt(); continue }
    if (c == "<" || c == ">" || (c == "&" && substr(s, i + 1, 1) == ">")) {
      if (inW && W ~ /^[0-9]+$/) { W = ""; inW = 0 } else endword()
      op = c; i++
      if (c == "&") { op = "&>"; i++; if (substr(s, i, 1) == ">") { op = op ">"; i++ } }
      else {
        c2 = substr(s, i, 1)
        if (c2 == c) { op = op c2; i++; if (c == "<") { c2 = substr(s, i, 1); if (c2 == "<") { op = op c2; i++ } else if (c2 == "-") { op = op c2; i++ } } }
        else if (c2 == "&" || c2 == "|" || (c == "<" && c2 == ">")) { op = op c2; i++ }
      }
      pushtok(op, 1); needt = 1
      if (op == "<<" || op == "<<-") { hdnext = 1; hdtab = (op == "<<-") }
      continue
    }
    if (c == "(") {
      if (patpos) { i++; continue }
      endword()
      if (TKn == 1 && match(substr(s, i + 1), /^[ \t]*\)/)) {
        red(TKL[1], "function definition " shown(TK[1]) "() (it can shadow a command by name)")
        i += RLENGTH + 1; TKn = 0; continue
      }
      endstmt(); i++; continue
    }
    if (c == ")") {
      endword()
      if (patpos) { TKn = 0; patpos = 0 } else endstmt()
      i++; continue
    }
    if (c == ";") {
      endword()
      if (substr(s, i + 1, 1) == ";" || substr(s, i + 1, 1) == "&") { endstmt(); if (casedepth > 0) patpos = 1; i += 2; continue }
      endstmt(); i++; continue
    }
    if (c == "&" || c == "|") {
      endword()
      isp = (c == "|" && substr(s, i + 1, 1) != "|")
      if (substr(s, i + 1, 1) == c || (c == "|" && substr(s, i + 1, 1) == "&")) i++
      if (patpos) TKn = 0; else { endstmt(); if (isp) PIPEIN = 1 }
      i++; continue
    }
    W = W c; inW = 1; i++
  }
  endword(); endstmt()
}
function drain(   qi) {
  qi = 1
  while (qi <= qn) { lexone(QT[qi], QL[qi]); qi++ }
  qn = 0
}
function repl_expr(s,   o, a, b) {
  o = ""
  while ((a = index(s, "${{")) > 0) {
    b = index(substr(s, a), "}}")
    if (b == 0) { o = o substr(s, 1, a - 1) "\003X\003"; s = ""; break }
    o = o substr(s, 1, a - 1) "\003X\003"; s = substr(s, a + b + 1)
  }
  return o s
}

# shell_ok(v): the only `shell:` values the scanner reads with certainty (the exact GitHub default forms)
function shell_ok(v) {
  sub(/[ \t]+#.*$/, "", v); v = trim(v); gsub(/^["']|["']$/, "", v); v = trim(v)
  return (v == "" || v == "bash" || v == "sh" || v == "bash -e {0}" || v == "sh -e {0}" || v == "bash --noprofile --norc -eo pipefail {0}")
}
# an ownership word in a step's NON-run text (github-script body, with: values, env): fs.chownSync, setfacl, ...
function nonrun_prim(txt) { return (txt ~ /(^|[^A-Za-z0-9_])(l|f)?(chown|chgrp)(Sync)?([^A-Za-z0-9_]|$)|setfacl|chacl/) }
function unp(msg) { if (!UNPF) { UNPF = 1; UNPM = msg } }
# jsstep(): every `script:` body of a github-script step (or of any step with a script: key) must pass jsbad()
function jsstep(   L, ind, v, body, k, why, first, found, bl) {
  found = 0; why = ""
  if (OTHERTXT ~ /[{,][ \t]*["']?script["']?[ \t]*:/ || OTHERTXT ~ /(^|\n)[ \t]*["']script["'][ \t]*:/) { redt("JS", ITEMLN, "script: sits in a flow mapping or a quoted key: its JavaScript body is not read"); return }
  for (L = ITEMLN; L < CURLI; L++) {
    if (FL[L] !~ /^[ \t]*(- )?script[ \t]*:/) continue
    found++; ind = indent(FL[L]); v = FL[L]; sub(/^[ \t]*(- )?script[ \t]*:[ \t]*/, "", v); body = ""
    if (v ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) { for (k = L + 1; k < CURLI; k++) { if (FL[k] ~ /^[ \t]*$/) { body = body "\n"; continue } if (indent(FL[k]) <= ind) break; body = body FL[k] "\n" } }
    else { body = v "\n"; for (k = L + 1; k < CURLI; k++) { if (FL[k] ~ /^[ \t]*$/ || indent(FL[k]) <= ind) break; body = body FL[k] "\n" } }
    why = jsbad(body)
    if (why != "") {
      bl = L; for (k = L; k < CURLI; k++) if (jsbad(FL[k]) != "") { bl = k; break }
      redt("JS", bl, "JavaScript body can run a command or reach an ownership call (" why ")")
    }
  }
  if (!found && USESV ~ /github-script/) redt("JS", ITEMLN, "github-script step without a block-form script: key: its JavaScript body is not read")
}
function flushstep() {
  if (!INSTEP) return
  if (UNPF) { UNPARSE++; redt("UNPARSE", ITEMLN, "step cannot be read with certainty (" UNPM ")") }
  else {
    SCANNED++
    if (!shell_ok(SHELLK)) redt("SHELL", SHELLLN, "shell: " SHELLK " is not bash, sh or an exact default form: the step's text is read by an interpreter the scanner does not model")
    if (OTHERTXT != "" && nonrun_prim(OTHERTXT)) redt("PRIM", ITEMLN, "a non-run field of the step names an ownership primitive (chown/chgrp/setfacl)")
    if (USESV ~ /^["']?docker:\/\//) redt("INTERP", ITEMLN, "uses: docker:// runs an image the scanner does not read")
    if (USESV ~ /github-script/ || OTHERTXT ~ /(^|\n)[ \t]*script[ \t]*:/) jsstep()
    if (RUNTXT != "") {
      STEPS++; SID = 1; SEQ = 0; qn = 0
      queue(repl_expr(RUNTXT), RUNLN); drain(); resolve_all()
    }
  }
  INSTEP = 0; RUNTXT = ""; SHELLK = ""; STEP = ""; OTHERTXT = ""; UNPF = 0; HASRUN = 0; HASSHELL = 0; USESV = ""
  delete ASGN; delete ASGV; delete ASGS; delete PLUS; delete BIND
}
function parse(   li, line, p, key, val, kcol, k, first, ind, txt, folded, cont, last, l2, v2, ii, rest, instr, stind, itind, kind, blk, hit) {
  instr = 0; stind = -1; itind = -1; kind = -1; INSTEP = 0; UNPF = 0; HASC = 0
  for (li = 1; li <= NR; li++) {
    CURLI = li
    line = FL[li]
    if (line ~ /^[ \t]*(#.*)?$/) continue
    if (line ~ /^\.\.\.([ \t]|$)/ || (line ~ /^---([ \t]|$)/ && HASC)) { flushstep(); instr = 0; pseudo(li, "second YAML document or document end marker: the reader scans one document"); continue }
    if (line ~ /^---([ \t]|$)/) continue
    HASC = 1
    ii = indent(line)
    # leaving the steps list
    if (instr && (ii < stind || (ii == stind && line !~ /^[ \t]*-([ \t]|$)/))) { flushstep(); instr = 0 }
    if (!instr) {
      if (line ~ /^[ \t]*using:[ \t]*["']?(node|docker)/) { pseudo(li, "action runs a JavaScript file or an image (runs.using node/docker): its code is not read"); continue }
      if (line ~ /^[ \t]*["']?steps["']?[ \t]*:/ && line !~ /^[ \t]*steps:[ \t]*(#.*)?$/) { pseudo(li, "steps: is not a plain block sequence (flow, alias, quoted key or inline value)"); continue }
      if (line ~ /[{,][ \t]*["']?(steps|run)["']?[ \t]*:/) { pseudo(li, "steps/run inside a flow mapping"); continue }
      if (line ~ /(:|-)[ \t]+[&*][A-Za-z_][A-Za-z0-9_-]*([ \t]|$)/ || line ~ /^[ \t]*<<[ \t]*:/) { pseudo(li, "YAML anchor, alias or merge key: the content it stands for is not read"); continue }
      if (line ~ /^[ \t]*steps:[ \t]*(#.*)?$/) { instr = 1; stind = ii; itind = -1; continue }
      if (line ~ /^[ \t]*run:[ \t]*[^ \t#]/) { pseudo(li, "run: outside a steps list"); continue }
      if (line ~ /^[ \t]*shell:/) {
        v2 = line; sub(/^[ \t]*shell:[ \t]*/, "", v2)
        if (!shell_ok(v2)) redt("SHELL", li, "defaults shell: is not bash, sh or an exact default form")
      }
      # skip a block scalar body so its text is never read as keys
      p = line; sub(/^[ \t]*(- )?/, "", p); val = p; sub(/^[^:]*:[ \t]*/, "", val)
      if (p ~ /^[A-Za-z_"'][^:]*:/ && val ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) {
        kcol = length(line) - length(p)
        for (k = li + 1; k <= NR; k++) { if (FL[k] ~ /^[ \t]*$/) continue; if (indent(FL[k]) <= kcol) break; li = k }
      }
      continue
    }
    # inside steps
    if (line ~ /^[ \t]*-([ \t]|$)/ && (itind < 0 || ii == itind) && ii >= stind) {
      if (itind < 0) itind = ii
      flushstep(); INSTEP = 1; SEEN++; ITEMLN = li
      rest = line; sub(/^[ \t]*-[ \t]*/, "", rest)
      kind = length(line) - length(rest)
      if (rest == "" || rest ~ /^#/) { unp("bare dash: the step's keys are on following lines"); kind = -1; continue }
      if (rest ~ /^[{\[&*!?|>"']/ || rest ~ /^<<[ \t]*:/ || rest !~ /^[A-Za-z_][A-Za-z0-9_-]*[ \t]*:/) { unp("flow, anchor, alias, tag, quoted or non-mapping step entry"); continue }
      line = substr("                                                                ", 1, kind) rest
      ii = kind
    } else if (line ~ /^[ \t]*-([ \t]|$)/ && ii < itind) { flushstep(); pseudo(li, "list entry shallower than the steps list items"); continue }
    if (!INSTEP) { pseudo(li, "content in the steps list before the first entry"); continue }
    if (UNPF) continue
    # a step key line: only the step's own key column counts
    if (ii == kind) {
      p = line; sub(/^[ \t]*/, "", p)
      if (p !~ /^[A-Za-z_][A-Za-z0-9_-]*[ \t]*:([ \t]|$)/) { unp("step key that is not a plain key (quoted, alias, merge, complex)"); continue }
      key = p; sub(/[ \t]*:.*$/, "", key); val = p; sub(/^[^:]*:[ \t]*/, "", val)
      if (val ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) {
        folded = (substr(val, 1, 1) == ">"); txt = ""; first = 0; ind = 0; last = li
        for (k = li + 1; k <= NR; k++) {
          if (FL[k] ~ /^[ \t]*$/) continue
          if (indent(FL[k]) <= ii) break
          last = k; if (!first) { first = k; ind = indent(FL[k]) }
        }
        if (first) for (k = first; k <= last; k++) { l2 = (FL[k] ~ /^[ \t]*$/) ? "" : substr(FL[k], ind + 1); txt = txt (k == first ? "" : (folded ? " " : "\n")) l2 }
        if (key == "run") { if (HASRUN++) unp("duplicate run key"); RUNTXT = txt; RUNLN = first ? first : li }
        else if (key == "shell") { if (HASSHELL++) unp("duplicate shell key"); SHELLK = val; SHELLLN = li }
        else if (key != "name") OTHERTXT = OTHERTXT "\n" txt
        li = last; continue
      }
      if (key == "name") { v2 = val; gsub(/^["']|["']$/, "", v2); if (STEP == "") STEP = v2; continue }
      if (key == "shell") { if (HASSHELL++) unp("duplicate shell key"); SHELLK = val; SHELLLN = li; continue }
      if (key == "run") {
        if (HASRUN++) { unp("duplicate run key"); continue }
        if (val == "" ) { unp("run: with a nested value"); continue }
        txt = val; cont = li
        if (txt ~ /^"/ && txt ~ /"[ \t]*$/) { sub(/^"/, "", txt); sub(/"[ \t]*$/, "", txt); gsub(/\\"/, "\"", txt) }
        else if (txt ~ /^'/ && txt ~ /'[ \t]*$/) { sub(/^'/, "", txt); sub(/'[ \t]*$/, "", txt); gsub(/''/, "'", txt) }
        for (k = li + 1; k <= NR; k++) { if (FL[k] ~ /^[ \t]*$/ || indent(FL[k]) <= ii) break; txt = txt " " trim(FL[k]); cont = k }
        RUNTXT = txt; RUNLN = li; li = cont; continue
      }
      if (key == "uses") USESV = val
      OTHERTXT = OTHERTXT "\n" val
      continue
    }
    # deeper than the key column: the body of a non-run key (env:, with:, ...): its text is checked for ownership words
    if (ii > kind) { OTHERTXT = OTHERTXT "\n" line; continue }
    unp("line shallower than the step's keys but inside the steps list")
  }
  CURLI = NR + 1; flushstep()
}
BEGIN {
  F = ""; STEPS = 0; WORDS = 0; allowed = 0; SEEN = 0; SCANNED = 0; UNPARSE = 0; qn = 0
  initlists()
  af = ENVIRON["ALLOW"]
  while (af != "" && (getline row < af) > 0) {
    if (row ~ /^[ \t]*(#|$)/) continue
    split(row, R, "\t")
    if (R[4] != "") ALLOW[R[1] "\t" R[2] "\t" R[3]] = 1
  }
}
FNR == 1 { F = FILENAME; FK = F; if (F ~ /action\.ya?ml$/) { p = F; sub(/\/[^\/]*$/, "", p); FK = bn(p) "/action.yml" } else FK = bn(F) }
{ FL[NR] = $0 }
END {
  parse()
  for (k in USED) print "ALLOWUSED " k
  print "OSCAN " SEEN " " SCANNED " " UNPARSE " " WORDS " " allowed
  exit 0
}
