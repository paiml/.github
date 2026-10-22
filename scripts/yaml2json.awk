# yaml2json.awk — block-style YAML subset -> JSON, so the signer guards need no yq (the clean-room fleet has none).
# Supported: block maps, block sequences, plain/'single'/"double" scalars, | and > block scalars (-, +), {} and [], full-line
# and trailing comments. ANYTHING ELSE (anchors, aliases, tags, non-empty flow collections, tabs, multi-doc) is a hard
# error, exit 2: an unreadable file is a NO-GO, never a pass.
function die(m) { printf "yaml2json: line %d: %s\n", NR_cur, m > "/dev/stderr"; failed = 1; exit 2 }
function jstr(s,   o, i, c) {
  o = "\""
  for (i = 1; i <= length(s); i++) {
    c = substr(s, i, 1)
    if (c == "\\") o = o "\\\\"; else if (c == "\"") o = o "\\\""; else if (c == "\n") o = o "\\n"
    else if (c == "\t") o = o "\\t"; else if (c == "\r") o = o "\\r"; else o = o c
  }
  return o "\""
}
function scalar(v,   q, e, s, i, c) {
  sub(/^[ ]+/, "", v)
  if (v == "") return "null"
  q = substr(v, 1, 1)
  if (q == "\"" || q == "'") {
    s = ""; i = 2
    while (i <= length(v)) {
      c = substr(v, i, 1)
      if (q == "'" && c == "'") { if (substr(v, i + 1, 1) == "'") { s = s "'"; i += 2; continue } break }
      if (q == "\"" && c == "\"") break
      if (q == "\"" && c == "\\") { i++; e = substr(v, i, 1)
        if (e == "n") s = s "\n"; else if (e == "t") s = s "\t"; else if (e == "\"" || e == "\\" || e == "/") s = s e; else die("unsupported escape \\" e)
        i++; continue }
      s = s c; i++
    }
    if (i > length(v)) die("unterminated quoted scalar")
    e = substr(v, i + 1); if (e !~ /^[ ]*(#.*)?$/) die("text after a quoted scalar")
    return jstr(s)
  }
  if (q == "&" || q == "*" || q == "!" || q == "%" || q == "@" || q == "`") die("anchor, alias, tag or reserved indicator")
  sub(/[ ]+#.*$/, "", v); sub(/[ ]+$/, "", v)
  if (v == "{}") return "{}"
  if (v == "[]") return "[]"
  if (q == "{" || q == "[") die("non-empty flow collection")
  if (v == "true") return "true"; if (v == "false") return "false"; if (v == "null" || v == "~") return "null"
  if (v ~ /^-?(0|[1-9][0-9]*)$/) return v
  return jstr(v)
}
function sep(   f) { f = sp; if (cnt[f]++) out = out ","; }
function closeto(n) { while (sp > 0 && ind[sp] > n) { out = out (typ[sp] == "o" ? "}" : "]"); sp-- } }
function openframe(t, n) { sp++; ind[sp] = n; typ[sp] = t; cnt[sp] = 0; fid[sp] = ++nfid; out = out (t == "o" ? "{" : "[") }
function block(parent_n, hdr,   chomp, j, l, bi, body, txt, nl, k, fold, line) {
  if (hdr !~ /^[|]-?[ ]*$/) die("only literal block scalars (pipe, pipe-minus) are read; folded, keep and indentation indicators are refused")
  chomp = (hdr ~ /-/) ? "-" : (hdr ~ /\+/ ? "+" : ""); fold = (substr(hdr, 1, 1) == ">")
  body = ""; nl = 0; bi = -1
  for (j = i + 1; j <= N; j++) {
    l = L[j]
    if (l ~ /^[ ]*$/) { nl++; pend[nl] = ""; continue }
    k = match(l, /[^ ]/) - 1
    if (k <= parent_n) break
    if (bi < 0) bi = k
    if (k < bi) break
    for (nl = nl; nl > 0; nl--) { body = body (fold ? "" : "\n") }
    nl = 0
    line = substr(l, bi + 1)
    body = body (body == "" && !started ? "" : "") line "\n"
    started = 1
  }
  started = 0
  i = j - 1
  txt = body
  if (fold) { gsub(/\n/, " ", txt); sub(/ $/, "\n", txt) }
  if (chomp == "-") sub(/\n+$/, "", txt)
  return jstr(txt)
}
{ L[NR] = $0 }
END {
  if (failed) exit 2
  N = NR; sp = 0; pending = 0; out = ""; started = 0
  for (i = 1; i <= N; i++) {
    NR_cur = i; line = L[i]
    if (line ~ /\t/ && line !~ /^[ ]*#/) { if (match(line, /^[ ]*\t/)) die("tab indentation") }
    if (line ~ /^[ ]*(#.*)?$/) continue
    if (line ~ /^---[ ]*$/ && i == 1) continue
    if (line ~ /^(---|\.\.\.)/) die("multi-document stream")
    n = match(line, /[^ ]/) - 1; c = substr(line, n + 1)
    # resolve a key whose value is on the following lines
    if (pending) {
      if (c ~ /^-([ ]|$)/ && n >= pn) { openframe("a", n) }
      else if (n > pn) { openframe("o", n) }
      else { out = out "null" }
      pending = 0
    }
    isseq = 0
    while (c ~ /^-([ ]|$)/) {   # sequence item (possibly nested "- - x" is refused below)
      closeto(n)
      if (sp == 0 || ind[sp] != n || typ[sp] != "a") { if (sp == 0 && out != "") die("second root"); openframe("a", n) }
      sep()
      rest = substr(c, 2); m = match(rest, /[^ ]/)
      if (m == 0) die("empty sequence item")
      c = substr(rest, m); n = n + 1 + m - 1; isseq = 1
      if (c ~ /^-([ ]|$)/) die("nested sequence on one line")
      break
    }
    if (match(c, /^("[^"]*"|'[^']*'|[A-Za-z0-9_.\/-]+)[ ]*:([ ]|$)/)) {
      kt = substr(c, 1, RLENGTH); sub(/[ ]*:([ ]|$)$/, "", kt)
      v = substr(c, RLENGTH + 1)
      if (kt ~ /^"/) kt = substr(kt, 2, length(kt) - 2); else if (kt ~ /^'/) kt = substr(kt, 2, length(kt) - 2)
      closeto(n)
      if (sp == 0 || ind[sp] != n || typ[sp] != "o") { if (sp == 0 && out != "") die("second root"); openframe("o", n) ; if (isseq) cnt[sp] = 0 }
      if (!isseq || cnt[sp] > 0) sep(); else cnt[sp]++
      if ((fid[sp] SUBSEP kt) in seen) die("duplicate key " kt); seen[fid[sp] SUBSEP kt] = 1
      out = out jstr(kt) ":"
      sub(/^[ ]+/, "", v)
      if (v == "" || v ~ /^#/) { pending = 1; pn = (isseq ? n : n) }
      else if (v ~ /^[|>][-+0-9]*[ ]*(#.*)?$/) { sub(/[ ]*#.*$/, "", v); out = out block(n, v) }
      else out = out scalar(v)
    } else {
      if (!isseq) { if (sp == 0) { out = scalar(c); continue } die("not a key or a sequence item: " c) }
      if (c ~ /^[|>][-+0-9]*[ ]*$/) out = out block(n - 2, c); else out = out scalar(c)
    }
  }
  if (pending) out = out "null"
  closeto(-1)
  print out
}
