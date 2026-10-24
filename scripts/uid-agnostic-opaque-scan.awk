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
# Output: FAIL[OPAQUE] lines, "ALLOWUSED <key>" per row that matched, and "OSCAN <steps> <words> <allowed>".
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
function red(ln, msg,   key) {
  key = FK "\t" STEP "\t" trim(FL[ln])
  if (key in ALLOW) { USED[key] = 1; allowed++; return }
  print "FAIL[OPAQUE] " F ":" ln ": " msg ": " trim(FL[ln]); bad = 1
  print "ROW\t" key "\t<reason>"
}
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
# evalrange(a, b): the statement held in TK[a..b] (raw words)
function evalrange(a, b, depth,   j, t, bt, w, v, k, e, p, pl, sc, ex) {
  j = a
  while (j <= b) {
    if (RD[j]) { j++; continue }
    t = lit(TK[j]); bt = bn(t)
    if (t ~ /^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=/ || TK[j] ~ /^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=/) { record_asg(TK[j], TKL[j]); j++; continue }
    if (bt ~ /^(do|then|else|elif|if|while|until|time|!|nohup|setsid|builtin|\{|\}|done|fi|esac)$/) { j++; continue }
    if (bt == "sudo" || bt == "doas") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[ughCDprtTU]$/) j++; j++ } continue }
    if (bt == "command") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[vV]$/) return; j++ } continue }
    if (bt == "exec") { j++; while (j <= b && TK[j] ~ /^-/) j++; continue }
    if (bt == "env") { j++; while (j <= b && (TK[j] ~ /^-/ || TK[j] ~ /^[A-Za-z_][A-Za-z0-9_]*=/)) { if (TK[j] ~ /=/ && TK[j] !~ /^-/) record_asg(TK[j], TKL[j]); j++ } continue }
    if (bt == "nice") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] == "-n") j++; j++ } continue }
    if (bt == "ionice") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[ctnp]$/) j++; j++ } continue }
    if (bt == "timeout") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[ks]$/) j++; j++ } if (j <= b && TK[j] ~ /^[0-9.]+[smhd]?$/) j++; continue }
    if (bt == "xargs") { j++; while (j <= b && TK[j] ~ /^-/) { if (TK[j] ~ /^-[nIPLsEda]$/ || TK[j] ~ /^--(max-args|max-procs|replace|delimiter|arg-file|max-lines|max-chars|eof)$/) j++; j++ } continue }
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
  if (bt == "eval") { red(TKL[j], "eval runs text the scanner cannot read"); return }
  if (bt == "alias") { red(TKL[j], "alias redefines a command word"); return }
  if (bt == "source" || bt == ".") {
    for (k = j + 1; k <= b && (RD[k] || TK[k] ~ /^-/); k++) ;
    if (k <= b && lit(TK[k]) == "") red(TKL[j], "source of a path that is not a plain literal")
    return
  }
  if (bt ~ /^(sh|bash|dash|zsh|ksh|ash)$/) {
    for (k = j + 1; k <= b; k++) {
      if (RD[k]) continue
      if (TK[k] !~ /^-/) break
      if (TK[k] ~ /^-[A-Za-z]*c[A-Za-z]*$/) {
        p = (k + 1 <= b) ? TK[k + 1] : ""; e = unq(p)
        if (e == "\001") red(TKL[j], "shell -c with a payload that is not a literal string")
        else queue(e, TKL[k + 1])
        return
      }
    }
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
      for (e = k + 1; e <= b && TK[e] != "\\;" && TK[e] != "+" && TK[e] != ";"; e++) ;
      if (e > k + 1) evalrange(k + 1, e - 1, depth + 1)
    }
    return
  }
}
function endstmt(   k) {
  if (TKn > 0 && !patpos) { SEQ++; evalrange(1, TKn, 0) }
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
function lexone(s, ln,   n, i, c, c2, e, q, k, op, body, line2, dl, cut, stripped, hs) {
  n = length(s); i = 1; W = ""; inW = 0; TKn = 0; patpos = 0; dbl = 0; casedepth = 0; needt = 0; hdnext = 0; curln = ln; hn = 0
  delete HDST; delete HDSH
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
      if (substr(s, i + 1, 1) == c || (c == "|" && substr(s, i + 1, 1) == "&")) i++
      if (patpos) TKn = 0; else endstmt()
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
function flushstep() {
  if (RUNTXT != "") {
    if (SHELLK != "" && SHELLK !~ /^(bash|sh)([ \t]|$)/) { RUNTXT = ""; SKIPPED++ }
    else {
      STEPS++; SID = 1; SEQ = 0; qn = 0
      queue(repl_expr(RUNTXT), RUNLN); drain(); resolve_all()
    }
  }
  RUNTXT = ""; SHELLK = ""; STEP = ""
  delete ASGN; delete ASGV; delete ASGS; delete PLUS; delete BIND
}
function parse(   li, line, p, key, val, kcol, k, first, ind, txt, folded, cont, last, l2, v2) {
  for (li = 1; li <= NR; li++) {
    line = FL[li]
    if (line ~ /^[ \t]*- (name|uses|run|id|if|env|with|shell|working-directory|continue-on-error|timeout-minutes):/) flushstep()
    if (line !~ /^[ \t]*(- )?[A-Za-z_][A-Za-z0-9_-]*:/) continue
    p = line; sub(/^[ \t]*(- )?/, "", p); kcol = length(line) - length(p)
    key = p; sub(/:.*$/, "", key); val = p; sub(/^[^:]*:[ \t]*/, "", val)
    if (val ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) {
      folded = (substr(val, 1, 1) == ">"); txt = ""; first = 0; ind = 0; last = li
      for (k = li + 1; k <= NR; k++) {
        if (FL[k] ~ /^[ \t]*$/) continue
        if (indent(FL[k]) <= kcol) break
        last = k; if (!first) { first = k; ind = indent(FL[k]) }
      }
      if (first) for (k = first; k <= last; k++) { l2 = (FL[k] ~ /^[ \t]*$/) ? "" : substr(FL[k], ind + 1); txt = txt (k == first ? "" : (folded ? " " : "\n")) l2 }
      if (key == "run") { RUNTXT = txt; RUNLN = first ? first : li }
      li = last
      continue
    }
    if (key == "name") { v2 = val; gsub(/^["']|["']$/, "", v2); if (STEP == "") STEP = v2; continue }
    if (key == "shell") { SHELLK = val; gsub(/^["']|["']$/, "", SHELLK); continue }
    if (key == "run" && val != "") {
      txt = val; cont = li
      if (txt ~ /^"/ && txt ~ /"[ \t]*$/) { sub(/^"/, "", txt); sub(/"[ \t]*$/, "", txt); gsub(/\\"/, "\"", txt) }
      else if (txt ~ /^'/ && txt ~ /'[ \t]*$/) { sub(/^'/, "", txt); sub(/'[ \t]*$/, "", txt); gsub(/''/, "'", txt) }
      for (k = li + 1; k <= NR; k++) { if (FL[k] ~ /^[ \t]*$/ || indent(FL[k]) <= kcol) break; txt = txt " " trim(FL[k]); cont = k }
      RUNTXT = txt; RUNLN = li; li = cont
    }
  }
  flushstep()
}
BEGIN {
  F = ""; STEPS = 0; WORDS = 0; allowed = 0; SKIPPED = 0; qn = 0
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
  print "OSCAN " STEPS " " WORDS " " allowed
  exit 0
}
