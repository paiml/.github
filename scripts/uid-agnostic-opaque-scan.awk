# infra#2349 OPAQUE class scan, one workflow / composite-action file per run (called by
# test-uid-agnostic-chown.sh). Closes the class behind three scanner holes found at f0e60da:
#   X+=own appends, `alias c=chown`, and "$X$Y" in a step with no chown token.
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
function bind(name) { if (name ~ /^[A-Za-z_][A-Za-z0-9_]*$/) BIND[name] = 1 }
# identifiers on the left of an assignment operator inside (( )) / $(( )) / ${V:=w}
function bindarith(t,   a, k, m) {
  while (match(t, /[A-Za-z_][A-Za-z0-9_]*[ \t]*(\+|-|\*|\/|%|<<|>>|&|\^|\|)?=[^=]/)) {
    m = substr(t, RSTART, RLENGTH); sub(/[^A-Za-z0-9_].*$/, "", m); bind(m); t = substr(t, RSTART + RLENGTH)
  }
}
function record_asg(tok, ln,   nm, pl, val, sub1) {
  nm = tok; sub(/[+\[=].*$/, "", nm)
  if (tok ~ /^[A-Za-z_][A-Za-z0-9_]*\[/) { bind(nm); return }
  pl = (tok ~ /^[A-Za-z_][A-Za-z0-9_]*\+=/)
  val = tok; sub(/^[A-Za-z_][A-Za-z0-9_]*\+?=/, "", val)
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
    if (ASGN[nm] == 1 && !(nm in PLUS) && !(nm in BIND) && ASGS[nm] < DSQ[i] && lit(ASGV[nm]) != "" && !dangerous(bn(v))) continue
    red(DLN[i], "command word " shown(DW[i]) " is a variable that is not assigned exactly once, by a plain VAR=literal, before this use (+=, a second assignment, read/for/:= binding, env-only or a dangerous literal)")
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
# a pipe may feed only a consumer that reads data: anything else could execute the text
function safe_consumer(b) {
  return (b ~ /^(cat|grep|egrep|fgrep|sed|awk|gawk|mawk|cut|tr|sort|uniq|head|tail|tee|wc|jq|read|base64|xxd|od|sha256sum|sha1sum|sha512sum|md5sum|b2sum|gzip|gunzip|zcat|bzip2|xz|zstd|column|paste|join|comm|diff|cmp|fold|nl|rev|less|more|xargs|true|false|test|\[|\[\[|:|curl|wget|gh|docker|cosign|openssl|gpg|git|cargo|rustc|jq|sponge|mapfile|readarray|while|until|printf|echo|date|sleep|logger|cmp|realpath|dirname|basename|stat|ls|find|rm|mkdir|touch|mv|cp|ln|df|du|free|ps|lsof|ss|ip|tput|wall|mail|sendmail|nproc|uname|id|whoami|env|sudo|command|tac|expand|unexpand|split|csplit|shuf|seq|yes|timeout|nice|ionice|time|stdbuf|flock|systemctl|journalctl)$/)
}
# evalrange(a, b): the statement held in TK[a..b] (raw words)
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
  if (XREPL && (bt ~ /^(sh|bash|dash|zsh|ksh|ash|eval)$/)) { redt("INTERP", TKL[j], "xargs replacement string fed into a shell or eval"); return }
  if (PIPED && !safe_consumer(bt) && bt !~ /^(sh|bash|dash|zsh|ksh|ash|eval)$/) { redt("INTERP", TKL[j], "piped text reaches " bt ", which is not a known data consumer (it may execute it)"); return }
  for (k = a; k <= b; k++) if (RD[k] == 1 && TK[k] ~ /^<<[<-]?$/ && !safe_consumer(bt) && bt !~ /^(sh|bash|dash|zsh|ksh|ash|eval)$/) { redt("INTERP", TKL[j], "a heredoc or here-string feeds text to " bt ", which is not a known data consumer (it may execute it)"); return }
  if (bt == "eval") { redt("INTERP", TKL[j], "eval runs text the scanner cannot read"); return }
  if (bt == "alias") { red(TKL[j], "alias redefines a command word"); return }
  if (bt == "source" || bt == ".") { redt("INTERP", TKL[j], bt " runs a file the scanner does not read"); return }
  if (bt ~ /^(sh|bash|dash|zsh|ksh|ash)$/) { shellrange(j, b); return }
  if (bt ~ /^(python[0-9.]*|perl|ruby|node|nodejs|php|pwsh|lua|deno|bun|tclsh|osascript|expect|irb|jshell|Rscript|julia|swift|go)$/ && bt != "go") { redt("INTERP", TKL[j], bt " is an interpreter: the program it runs is not read by this scanner"); return }
  if (bt ~ /^(nsenter|chroot|flock|script|watch|parallel|stdbuf|taskset|docker|podman|ssh|unshare|setpriv|capsh|sg|newgrp|sshpass|kubectl|lxc|systemd-run|firejail|bwrap)$/) {
    for (k = j + 1; k <= b; k++) if (!RD[k] && bn(lit(TK[k])) ~ /^(sh|bash|dash|zsh|ksh|ash|eval|su|runuser)$/) { evalrange(k, b, depth + 1); return }
    if (PIPED && bt ~ /^(nsenter|chroot|script|ssh|unshare|setpriv|capsh|sg|newgrp|sshpass|kubectl|lxc|systemd-run|firejail|bwrap)$/) redt("INTERP", TKL[j], "piped text reaches " bt ", which can run it as a command on the other side")
    return
  }
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
    for (k = j + 1; k <= b; k++) if (!RD[k] && TK[k] ~ /^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=/) record_asg(TK[k], TKL[k]); else if (!RD[k] && TK[k] !~ /^-/) bind(lit(TK[k]))
    for (k = j + 1; k <= b; k++) if (TK[k] ~ /^-[A-Za-z]*n/) bind(lit(TK[k + 1]))
    return
  }
  if (bt ~ /^(read|mapfile|readarray|getopts|unset)$/) { for (k = j + 1; k <= b; k++) if (!RD[k] && TK[k] !~ /^-/) bind(lit(TK[k])); return }
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
  if (TKn > 0 && !patpos) { SEQ++; PIPED = PIPEIN; PIPEIN = 0; XREPL = 0; primscan(1, TKn); evalrange(1, TKn, 0) }
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
function flushstep() {
  if (!INSTEP) return
  if (UNPF) { UNPARSE++; redt("UNPARSE", ITEMLN, "step cannot be read with certainty (" UNPM ")") }
  else {
    SCANNED++
    if (!shell_ok(SHELLK)) redt("SHELL", SHELLLN, "shell: " SHELLK " is not bash, sh or an exact default form: the step's text is read by an interpreter the scanner does not model")
    if (OTHERTXT != "" && nonrun_prim(OTHERTXT)) redt("PRIM", ITEMLN, "a non-run field of the step names an ownership primitive (chown/chgrp/setfacl)")
    if (RUNTXT != "") {
      STEPS++; SID = 1; SEQ = 0; qn = 0
      queue(repl_expr(RUNTXT), RUNLN); drain(); resolve_all()
    }
  }
  INSTEP = 0; RUNTXT = ""; SHELLK = ""; STEP = ""; OTHERTXT = ""; UNPF = 0; HASRUN = 0; HASSHELL = 0
  delete ASGN; delete ASGV; delete ASGS; delete PLUS; delete BIND
}
function parse(   li, line, p, key, val, kcol, k, first, ind, txt, folded, cont, last, l2, v2, ii, rest, instr, stind, itind, kind, blk, hit) {
  instr = 0; stind = -1; itind = -1; kind = -1; INSTEP = 0; UNPF = 0; HASC = 0
  for (li = 1; li <= NR; li++) {
    line = FL[li]
    if (line ~ /^[ \t]*(#.*)?$/) continue
    if (line ~ /^\.\.\.([ \t]|$)/ || (line ~ /^---([ \t]|$)/ && HASC)) { flushstep(); instr = 0; pseudo(li, "second YAML document or document end marker: the reader scans one document"); continue }
    if (line ~ /^---([ \t]|$)/) continue
    HASC = 1
    ii = indent(line)
    # leaving the steps list
    if (instr && (ii < stind || (ii == stind && line !~ /^[ \t]*-([ \t]|$)/))) { flushstep(); instr = 0 }
    if (!instr) {
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
      OTHERTXT = OTHERTXT "\n" val
      continue
    }
    # deeper than the key column: the body of a non-run key (env:, with:, ...): its text is checked for ownership words
    if (ii > kind) { OTHERTXT = OTHERTXT "\n" line; continue }
    unp("line shallower than the step's keys but inside the steps list")
  }
  flushstep()
}
BEGIN {
  F = ""; STEPS = 0; WORDS = 0; allowed = 0; SEEN = 0; SCANNED = 0; UNPARSE = 0; qn = 0
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
