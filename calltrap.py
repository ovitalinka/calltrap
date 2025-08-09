#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
calltrap — offline hunter for nested calls inside Ethereum calldata.

What it does (no ABI, no RPC):
  • Parses a top-level calldata (0x...), splits selector/head/tail (32-byte words).
  • Detects dynamic regions (bytes / bytes[]) via ABI offset patterns.
  • Walks into those regions and looks for embedded call frames that begin with a 4-byte selector.
  • Reconstructs candidate subcalls (selector + head/tail size guesses).
  • Labels well-known risky selectors: approve, setApprovalForAll, permit, upgradeTo, initialize, multicall.
  • Emits JSON + pretty console output + optional tiny SVG badge.

Use cases:
  • Spot “hidden” token approvals bundled in multicalls.
  • Review initializer payloads before proxy upgrades (look for upgradeTo/initialize).
  • Triage suspicious “data” blobs passed through generic hooks.

Examples:
  $ python calltrap.py analyze 0x8a8c523c... --pretty
  $ python calltrap.py analyze data.txt --json report.json --svg badge.svg
  $ cat calldata.hex | python calltrap.py analyze - --pretty
"""

import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple

import click

# Known 4-byte selectors → friendly name (curated, high-signal)
KNOWN = {
    "095ea7b3": "approve(address,uint256)",
    "a9059cbb": "transfer(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "a22cb465": "setApprovalForAll(address,bool)",
    "208e7d3b": "permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)",  # alt sigs exist
    "d505accf": "permit(address,address,uint256,uint256,uint256,uint8,bytes32,bytes32)",
    "5ae401dc": "multicall(bytes[],address,bool,bool)",  # popular variants
    "ac9650d8": "multicall(bytes[])",
    "9baa204f": "multicall(uint256,bytes[])",
    "8129fc1c": "initialize(address)",                    # generic; many variants, watch for
    "f2fde38b": "transferOwnership(address)",
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "79ba5097": "execute(address,uint256,bytes)",        # generic exec
    "095ea7b3": "approve(address,uint256)",
}

RISKY_PREFIXES = {
    "approve": "HIGH",
    "setApprovalForAll": "HIGH",
    "permit": "MEDIUM",
    "upgradeTo": "HIGH",
    "upgradeToAndCall": "HIGH",
    "initialize": "MEDIUM",
    "execute": "MEDIUM",
    "multicall": "LOW",
    "transfer": "LOW",
    "transferFrom": "LOW",
}

# ------------------ helpers ------------------

def _strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h

def _as_bytes(h: str) -> bytes:
    h = _strip0x(h).lower()
    if len(h) % 2 != 0:
        raise click.ClickException("Hex length must be even.")
    try:
        return bytes.fromhex(h)
    except Exception as e:
        raise click.ClickException(f"Invalid hex: {e}")

def _u256(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0

def _chunks(bs: bytes, n: int) -> List[bytes]:
    return [bs[i:i+n] for i in range(0, len(bs), n)]

def _selector(h: str) -> str:
    h = _strip0x(h).lower()
    return h[:8] if len(h) >= 8 else ""

# ------------------ models ------------------

@dataclass
class Subcall:
    start: int           # byte offset relative to start of data (after the top selector)
    selector: str        # 8 hex chars
    friendly: Optional[str]
    length_guess: int    # guessed total length of this subcall frame (head+tail), or 0 if unknown
    risk: str            # LOW/MEDIUM/HIGH
    notes: List[str]

@dataclass
class Report:
    top_selector: str
    top_known: Optional[str]
    subcalls: List[Subcall]
    notes: List[str]

# ------------------ core logic ------------------

def _scan_dynamic_regions(data: bytes) -> List[Tuple[int, int]]:
    """
    Return list of (offset, length) for each dynamic region we can confidently parse
    using ABI layout (offset-> [len][bytes...] pattern). The offset is relative to data.
    """
    words = _chunks(data, 32)
    total = len(data)
    regions: List[Tuple[int,int]] = []
    # Head phase: any 32-byte word that looks like an offset into [0,total)
    for i, w in enumerate(words):
        off = _u256(w)
        if off % 32 != 0: 
            continue
        if 0 <= off <= total - 32:
            # try to read length at offset
            if off + 32 <= total:
                ln = _u256(data[off:off+32])
                # sanity: length must not exceed remaining bytes
                if 0 <= ln <= total - off - 32:
                    regions.append((off, 32 + ln))  # include the 32B length word
    # De-duplicate
    seen = set()
    uniq = []
    for r in regions:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return sorted(uniq, key=lambda x: x[0])

def _scan_bytes_array_region(data: bytes, start: int) -> List[Tuple[int,int]]:
    """
    If a region at 'start' encodes bytes[] (dynamic array of dynamic bytes), return
    list of (offset, total_len) for each element region relative to data.
    Layout:
      at start: [len N]
      then N items: [offset_i] (relative to start+32)
      then payloads at (start+32 + offset_i) as [len M][bytes M]
    """
    total = len(data)
    if start + 32 > total:
        return []
    n = _u256(data[start:start+32])
    index_base = start + 32
    # Check that we have N offsets
    if index_base + 32*n > total or n == 0 or n > 1024:
        return []
    items: List[Tuple[int,int]] = []
    for i in range(n):
        off_i = _u256(data[index_base + 32*i : index_base + 32*(i+1)])
        # offsets in bytes[] are relative to the start of the array data (index_base)
        at = index_base + off_i
        if at + 32 > total:
            return []
        ln = _u256(data[at:at+32])
        if ln < 0 or at + 32 + ln > total:
            return []
        items.append((at, 32 + ln))
    return items

def _guess_subcall_from_region(data: bytes, off: int, length: int) -> Optional[Subcall]:
    """
    Try to interpret a [len][bytes] region as an embedded call: 0x + 4-byte selector + payload.
    We accept if length>=36. We also attempt to infer total frame size by walking head pointers
    within that payload (lightweight).
    """
    if length < 36:
        return None
    # First 32 bytes: length word; then payload starts at off+32
    p0 = off + 32
    selector = data[p0:p0+4].hex()
    if len(selector) != 8:
        return None
    friendly = KNOWN.get(selector)
    risk = "LOW"
    notes: List[str] = []
    if friendly:
        for k, lvl in RISKY_PREFIXES.items():
            if friendly.startswith(k):
                risk = lvl
                break
        notes.append(f"known selector: {friendly}")
    else:
        notes.append("unknown selector")

    # Conservative length guess: try head-scan like top-level
    payload = data[p0+4 : off + length]
    words = _chunks(payload, 32)
    total = len(payload)
    # find any offsets; compute furthest extent
    extent = 0
    for w in words:
        v = _u256(w)
        if v % 32 == 0 and 0 <= v <= total - 32:
            ln = _u256(payload[v:v+32])
            if 0 <= ln <= total - v - 32:
                extent = max(extent, v + 32 + ln)
    guessed = 4 + max(extent, 32*len(words)) if words else length - 32
    guessed = min(guessed, length - 32)
    return Subcall(start=p0, selector=selector, friendly=friendly, length_guess=guessed, risk=risk, notes=notes)

def analyze_calldata(calldata_hex: str) -> Report:
    h = _strip0x(calldata_hex).lower()
    if len(h) < 8:
        raise click.ClickException("Calldata too short (need 4-byte selector).")
    top_sel = h[:8]
    body = _as_bytes(calldata_hex)[4:]  # drop the 4-byte selector
    notes: List[str] = []
    top_known = KNOWN.get(top_sel)
    if top_known:
        notes.append(f"Top-level selector: {top_known}")
    # 1) Scan dynamic regions in the top-level body
    regions = _scan_dynamic_regions(body)
    # 2) For each region, try bytes[] expansion; otherwise treat as bytes
    subcalls: List[Subcall] = []
    for off, ln in regions:
        # Try bytes[] view
        items = _scan_bytes_array_region(body, off)
        if items:
            for at, l in items:
                c = _guess_subcall_from_region(body, at, l)
                if c: subcalls.append(c)
        else:
            c = _guess_subcall_from_region(body, off, ln)
            if c: subcalls.append(c)
    # 3) As a last resort, slide a 4-byte window through the whole body at 32-byte boundaries
    #    to catch dumb-packed payloads: [len][selector|...] without ABI offsets.
    if not subcalls:
        words = _chunks(body, 32)
        for i, w in enumerate(words):
            if len(w) < 4: continue
            sel = w[:4].hex()
            if sel in KNOWN:
                subcalls.append(Subcall(start=i*32, selector=sel, friendly=KNOWN[sel], length_guess=32, risk=RISKY_PREFIXES.get(KNOWN[sel].split("(")[0], "LOW"), notes=["selector-like at word boundary"]))

    return Report(top_selector=top_sel, top_known=top_known, subcalls=subcalls, notes=notes)

# ------------------ CLI ------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """calltrap — hunt hidden calls inside calldata blobs (offline)."""
    pass

@cli.command("analyze")
@click.argument("input_arg", type=str)
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge (first match).")
@click.option("--pretty", is_flag=True, help="Human-readable output.")
def analyze_cmd(input_arg, json_out, svg_out, pretty):
    """
    Analyze a single 0x calldata, a file path with multiple calldatas (one per line),
    or '-' for stdin.
    """
    lines: List[str] = []
    if input_arg == "-":
        lines = [l.strip() for l in sys.stdin if l.strip()]
    elif os.path.isfile(input_arg):
        with open(input_arg, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    else:
        lines = [input_arg]

    reports: List[Report] = []
    for ln in lines:
        if not ln.lower().startswith("0x"):
            reports.append(Report(top_selector="", top_known=None, subcalls=[], notes=[f"skip (not hex calldata): {ln[:32]}…"]))
            continue
        try:
            rep = analyze_calldata(ln)
            reports.append(rep)
        except click.ClickException as e:
            reports.append(Report(top_selector="", top_known=None, subcalls=[], notes=[f"parse error: {e}"]))

    # Pretty
    if pretty:
        for r in reports:
            if not r.top_selector:
                click.echo(f"[skip] {r.notes[0]}")
                continue
            hdr = f"[{r.top_selector}] {r.top_known or 'unknown'}"
            click.echo(hdr)
            if r.subcalls:
                click.echo(f"  embedded calls: {len(r.subcalls)}")
                for sc in r.subcalls:
                    name = sc.friendly or "unknown"
                    click.echo(f"    @+{sc.start:04d}: {sc.selector}  {name}  risk={sc.risk}  len~{sc.length_guess}")
                    if sc.notes:
                        click.echo(f"      notes: {', '.join(sc.notes)}")
            else:
                click.echo("  embedded calls: (none detected)")
            if r.notes:
                click.echo("  top-notes: " + "; ".join(r.notes))

    # JSON
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([{
                "top_selector": r.top_selector,
                "top_known": r.top_known,
                "subcalls": [asdict(sc) for sc in r.subcalls],
                "notes": r.notes
            } for r in reports], f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    # SVG (first meaningful report)
    if svg_out:
        r = next((x for x in reports if x.top_selector), None)
        if r is None:
            click.echo("No valid calldata for SVG.")
        else:
            high = any(sc.risk == "HIGH" for sc in r.subcalls)
            med = any(sc.risk == "MEDIUM" for sc in r.subcalls)
            color = "#3fb950" if not (high or med) else "#d29922" if med and not high else "#f85149"
            title = (r.top_known or r.top_selector)
            sub = (r.subcalls[0].friendly or r.subcalls[0].selector) if r.subcalls else "no-embedded-calls"
            svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="640" height="48" role="img" aria-label="calltrap">
  <rect width="640" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    calltrap: {title} → {sub}
  </text>
  <circle cx="615" cy="24" r="6" fill="{color}"/>
</svg>"""
            with open(svg_out, "w", encoding="utf-8") as f:
                f.write(svg)
            click.echo(f"Wrote SVG badge: {svg_out}")

    # Default to JSON to stdout if nothing else
    if not (pretty or json_out or svg_out):
        click.echo(json.dumps([{
            "top_selector": r.top_selector,
            "top_known": r.top_known,
            "subcalls": [asdict(sc) for sc in r.subcalls],
            "notes": r.notes
        } for r in reports], indent=2))

if __name__ == "__main__":
    cli()
