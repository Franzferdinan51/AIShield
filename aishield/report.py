"""PDF summary reports — dependency-free minimal PDF writer.

A run report answers one question: what did the shield just do?
Sections: scan summary, applied steps, holds, skips, environment
warnings, and what still remains after the post-patch rescan.
"""
import os
import time
import textwrap

PAGE_W, PAGE_H = 612, 792
MARGIN = 48
LINE_H = 13.5
WRAP = 96


def _esc(s):
    s = (str(s).replace("\u2014", "--").replace("\u2013", "-")
         .replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"'))
    return (s.replace("\\", "\\\\").replace("(", "\\(")
            .replace(")", "\\)"))


def _wrap(line):
    if line == "":
        return [""]
    return textwrap.wrap(line, WRAP, replace_whitespace=False,
                         drop_whitespace=False) or [""]


def write_pdf(path, title, lines):
    all_lines = []
    for ln in lines:
        all_lines.extend(_wrap(ln))
    per_page = int((PAGE_H - 2 * MARGIN - 28) // LINE_H)
    pages = [all_lines[i:i + per_page]
             for i in range(0, len(all_lines), per_page)] or [["(empty)"]]
    objects = []

    def add(content):
        objects.append(content)
        return len(objects)

    font_id = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids = []
    content_ids = []
    for page_lines in pages:
        stream = ["BT /F1 15 Tf %.0f %.0f Td (%s) Tj ET"
                  % (MARGIN, PAGE_H - MARGIN, _esc(title))]
        y = PAGE_H - MARGIN - 26
        body = ["BT /F1 9.5 Tf %.0f %.0f Td" % (MARGIN, y)]
        for i, ln in enumerate(page_lines):
            if i:
                body.append("0 -%.1f Td" % LINE_H)
            body.append("(%s) Tj" % _esc(ln))
        body.append("ET")
        stream.append("\n".join(body))
        data = "\n".join(stream).encode("latin-1", "replace")
        cid = add(b"<< /Length %d >>\nstream\n" % len(data) + data + b"\nendstream")
        content_ids.append(cid)
        page_ids.append(None)  # filled after ids known
    kids = []
    for cid in content_ids:
        pid = add("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %d %d] "
                  "/Contents %d 0 R /Resources << /Font << /F1 %d 0 R >> >> >>"
                  % (0, PAGE_W, PAGE_H, cid, font_id))
        kids.append(pid)
    pages_id = add("<< /Type /Pages /Kids [%s] /Count %d >>"
                   % (" ".join("%d 0 R" % k for k in kids), len(kids)))
    # rewrite page objects with the real parent id
    for pid in kids:
        old = objects[pid - 1]
        objects[pid - 1] = old.replace("/Parent 0 0 R", "/Parent %d 0 R" % pages_id)
    catalog_id = add("<< /Type /Catalog /Pages %d 0 R >>" % pages_id)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        body = obj if isinstance(obj, bytes) else obj.encode("latin-1", "replace")
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += (b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
            % (len(objects) + 1, catalog_id, xref))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(bytes(out))
    return path


def run_report_lines(target, scan, outcome, after, ai_summary=None):
    from . import __version__
    ts = time.strftime("%Y-%m-%d %H:%M:%S %Z")
    findings = [f for f in scan["findings"] if f["confidence"] != "error"]
    kev = [f for f in findings if f["known_exploited"]]
    lines = [
        "AI Shield v%s — patch run report" % __version__,
        "When:    %s" % ts,
        "Target:  %s" % target,
        "",
        "SCAN BEFORE",
        "  items inventoried: %s" % scan.get("inventory_count", "?"),
        "  findings: %d (known-exploited / KEV: %d)"
        % (len(findings), len(kev)),
    ]
    for w in scan.get("warnings", []):
        lines.append("  warning: %s" % w)
    applied = [r for r in outcome.get("applied", []) if r.get("result") == "applied"]
    failed = [r for r in outcome.get("applied", []) if r.get("result") == "failed"]
    held = [r for r in outcome.get("applied", [])
            if r.get("result") == "held-by-decision"
            or (r.get("result") == "skipped-manual" and r.get("note"))]
    manual = [r for r in outcome.get("applied", [])
              if r.get("result") == "skipped-manual" and not r.get("note")]
    lines += ["", "APPLIED (%d)" % len(applied)]
    for r in applied:
        fix = (r.get("fixed_versions") or ["latest"])[0]
        lines.append("  - %s %s -> %s  [%s]"
                     % (r["name"], r["version"], fix, r.get("manager", "")))
        for c in r.get("cve_ids", [])[:4]:
            lines.append("      fixes %s" % c)
    if failed:
        lines += ["", "FAILED (%d)" % len(failed)]
        for r in failed:
            tail = [ln.strip() for ln in str(r.get("output_tail", "")).splitlines()
                    if ln.strip()]
            reason = (" — " + tail[-1][:90]) if tail else ""
            lines.append("  - %s (rc=%s)%s" % (r["name"], r.get("rc"), reason))
            diag = r.get("ai_diagnosis") or {}
            if diag.get("cause"):
                lines.append("      AI diagnosis: %s" % diag["cause"])
                if diag.get("next"):
                    lines.append("      next step: %s" % diag["next"])
    if held:
        lines += ["", "HELD (%d)" % len(held)]
        for r in held:
            lines.append("  - %s — %s"
                         % (r["name"], r.get("note")
                            or r.get("decision_reason") or r["result"]))
    if manual:
        lines += ["", "MANUAL STEPS (%d) — update via the vendor/app store"
                  % len(manual)]
        for r in manual:
            lines.append("  - %s (%s) — %s"
                         % (r["name"], r["version"], r["command"]))
    if ai_summary:
        lines += ["", "AI SUMMARY (generated by the shield's AI layer "
                  "from this run's data)"]
        for ln in str(ai_summary).splitlines():
            lines.append("  " + ln)
    warns = outcome.get("env_warnings") or []
    lines += ["", "ENVIRONMENT CHECK"]
    if warns:
        for w in warns:
            lines.append("  pip check on %s:" % w.get("python", "?"))
            for ln in str(w.get("pip_check", "")).splitlines():
                lines.append("    %s" % ln)
    else:
        lines.append("  pip check: clean (no broken requirements)")
    if after is not None:
        still = [f for f in after["findings"] if f["confidence"] != "error"]
        res_by_name = {}
        for r in outcome.get("applied") or []:
            res_by_name.setdefault(str(r.get("name", "")).lower(), r)
        before_ver = {}
        for f in findings:
            before_ver.setdefault(str(f.get("name", "")).lower(), f.get("version"))

        def _tag(f):
            r = res_by_name.get(str(f.get("name", "")).lower())
            if not r:
                return "not in this run's plan"
            if r.get("result") == "applied":
                old = before_ver.get(str(f.get("name", "")).lower())
                if old and old != f.get("version"):
                    return "PATCHED in this run (%s -> %s) — still listed: KEV name-matches carry no version range" % (old, f.get("version"))
                return "patch ran this run — still listed: KEV name-matches carry no version range"
            if str(r.get("result", "")).startswith("blocked"):
                return "BLOCKED — %s" % (r.get("note") or r.get("result"))
            return "held for manual update — %s" % (r.get("note") or r.get("result"))

        n_patched = sum(1 for f in still
                        if (res_by_name.get(str(f.get("name", "")).lower()) or {}).get("result") == "applied")
        lines += ["", "AFTER (post-patch rescan)",
                  "  findings remaining: %d (was %d)" % (len(still), len(findings))]
        if n_patched:
            lines.append("  of those, %d were patched in this run and remain listed "
                         "only because KEV" % n_patched)
            lines.append("  name-matches have no version bounds to clear against.")
        seen = set()
        for f in still[:25]:
            key = (f["name"], f["version"])
            if key in seen:
                continue
            seen.add(key)
            lines.append("  - %s %s — %s  [%s]"
                         % (f["name"], f["version"],
                            (f["cve_ids"] or [f["vuln_id"]])[0], _tag(f)))
    lines += ["", "Notes: dry-run plans never change a system. Applied steps",
              "are logged in data/patch-log.jsonl. Held steps require a",
              "human decision; manual steps are updated by the vendor."]
    return lines


def write_run_report(base_dir, target, scan, outcome, after):
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(base_dir, "data", "reports",
                        "patch-%s-%s.pdf" % (target, ts))
    # Interactive twin: the same run as structured JSON, so the GUI
    # can render it (filterable, expandable) instead of only offering
    # a static PDF.
    try:
        import json as _json
        steps = (outcome or {}).get("applied") or []
        counts = {}
        for st in steps:
            k = st.get("result") or "?"
            counts[k] = counts.get(k, 0) + 1
        sidecar = {
            "kind": "patch-run", "target": target,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "pdf": os.path.basename(path),
            "summary": {
                "findings_before": len((scan or {}).get("findings") or []),
                "findings_after": len((after or {}).get("findings") or []),
                "steps": len(steps), "results": counts,
                "env_warnings": (outcome or {}).get("env_warnings") or []},
            "findings_before": (scan or {}).get("findings") or [],
            "plan": (scan or {}).get("plan") or [],
            "outcome": outcome or {},
            "findings_after": (after or {}).get("findings") or [],
        }
        # The AI narrative is generated HERE, in the backend, so every
        # surface (PDF, GUI, MCP, CLI) carries the same summary.
        try:
            from . import ai as _ai
            summary = _ai.summarize_run(sidecar)
        except Exception:
            summary = None
        if summary:
            sidecar["ai_summary"] = summary
        with open(path[:-4] + ".json", "w") as f:
            _json.dump(sidecar, f, indent=1, default=str)
    except Exception:
        summary = None
    write_pdf(path, "AI Shield — patch report (%s)" % target,
              run_report_lines(target, scan, outcome, after,
                               ai_summary=summary))
    return path
