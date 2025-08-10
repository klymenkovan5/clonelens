#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
clonelens — offline ABI near-clone detector (SimHash + selector Jaccard).

What it does (offline):
  • Load 1..N ABI JSON files (array form, "abi": [...], or Etherscan-style {"result": "<json>"}).
  • Build features from function & event signatures (+ mutability flags).
  • Compute a 64-bit SimHash fingerprint per ABI.
  • Compute function selector sets (0x + keccak4) and Jaccard overlap.
  • Compare all pairs; output ranked clone candidates with scores.
  • Pretty console view, JSON/CSV, optional SVG badge for the closest pair.

Examples:
  $ python clonelens.py scan ./abis/*.json --pretty
  $ python clonelens.py match ./abis/*.json --json matches.json --csv pairs.csv --svg badge.svg --pretty
"""

import csv
import glob
import json
import os
import sys
import math
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Tuple, Iterable, Optional

import click
from eth_utils import keccak

# ---------------------- helpers ----------------------

def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_abi_any(path: str) -> List[Dict[str, Any]]:
    """
    Accepts:
      • Plain array ABI
      • Object with "abi": [...]
      • Etherscan-style {"result": "<json-string>"}
    """
    data = _read_json(path)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("abi"), list):
            return data["abi"]
        if "result" in data:
            try:
                arr = json.loads(data["result"])
                if isinstance(arr, list):
                    return arr
            except Exception:
                pass
    raise click.ClickException(f"Unrecognized ABI format: {path}")

def normalize_type(t: str) -> str:
    if t == "uint": return "uint256"
    if t == "int": return "int256"
    return t

def fn_signature(name: str, inputs: List[Dict[str, Any]]) -> str:
    types = ",".join(normalize_type(i.get("type", "")) for i in inputs)
    return f"{name}({types})"

def evsig_signature(name: str, inputs: List[Dict[str, Any]]) -> str:
    types = ",".join(normalize_type(i.get("type", "")) for i in inputs)
    return f"{name}({types})"

def fourbyte(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()

# ---------------------- SimHash (64-bit) ----------------------

def _hash64(s: str) -> int:
    # Use keccak and fold to 64 bits
    h = keccak(text=s)
    # fold 256 -> 64 by xor across 4 chunks
    x = int.from_bytes(h[:8], "big") ^ int.from_bytes(h[8:16], "big") ^ int.from_bytes(h[16:24], "big") ^ int.from_bytes(h[24:], "big")
    return x & ((1<<64)-1)

def simhash64(tokens: Iterable[Tuple[str, int]]) -> int:
    vec = [0]*64
    for tok, wt in tokens:
        hv = _hash64(tok)
        for i in range(64):
            bit = 1 if (hv >> i) & 1 else 0
            vec[i] += wt if bit else -wt
    out = 0
    for i in range(64):
        if vec[i] >= 0:
            out |= (1<<i)
    return out

def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()

def simhash_similarity(a: int, b: int) -> float:
    # Cosine-ish proxy: 1 - Hamming/64
    return 1.0 - (hamming(a, b) / 64.0)

# ---------------------- Models ----------------------

@dataclass
class ContractView:
    file: str
    name_hint: str
    functions: List[str]       # fn signatures
    events: List[str]          # event signatures
    selectors: List[str]       # 4-byte for functions
    simhash64: int

@dataclass
class PairReport:
    a: str
    b: str
    a_name: str
    b_name: str
    simhash_sim: float
    selector_jaccard: float
    score: float               # combined score
    common_selectors: List[str]
    only_a: int
    only_b: int

# ---------------------- Feature extraction ----------------------

def extract_contract_view(path: str) -> ContractView:
    abi = load_abi_any(path)
    fns: List[str] = []
    evs: List[str] = []
    sels: List[str] = []
    name_hint = os.path.splitext(os.path.basename(path))[0]

    for it in abi:
        typ = it.get("type", "function")
        if typ == "function":
            nm = it.get("name", "")
            sig = fn_signature(nm, it.get("inputs", []))
            fns.append(sig)
            sels.append(fourbyte(sig))
        elif typ == "event":
            nm = it.get("name", "")
            sig = evsig_signature(nm, it.get("inputs", []))
            evs.append(sig)
        elif typ in ("constructor","fallback","receive"):
            # incorporate as light tokens so constructions/fallback/payable shape matters slightly
            st = it.get("stateMutability", "nonpayable")
            fns.append(f"__{typ}__({st})")

    # Build tokens with simple weights
    tokens: List[Tuple[str,int]] = []

    # Functions: name + full signature + mutability hints
    for it in abi:
        if it.get("type","function") != "function":
            continue
        nm = it.get("name","")
        sig = fn_signature(nm, it.get("inputs",[]))
        st = it.get("stateMutability","nonpayable")
        tokens.append((nm.lower(), 3))
        tokens.append((sig.lower(), 5))
        tokens.append((f"mut:{st}", 2))
        # type tokens
        for inp in it.get("inputs",[]):
            tokens.append((f"type:{normalize_type(inp.get('type',''))}", 1))

    # Events
    for it in abi:
        if it.get("type") == "event":
            nm = it.get("name","")
            sig = evsig_signature(nm, it.get("inputs",[]))
            tokens.append((f"ev:{nm.lower()}", 2))
            tokens.append((f"evsig:{sig.lower()}", 3))

    # Global hints
    tokens.append((f"nfunc:{len(fns)}", 1))
    tokens.append((f"nevent:{len(evs)}", 1))
    tokens.append((f"nsel:{len(sels)}", 1))

    sh = simhash64(tokens)
    return ContractView(file=os.path.basename(path), name_hint=name_hint, functions=fns, events=evs, selectors=sorted(set(sels)), simhash64=sh)

def jaccard(a: List[str], b: List[str]) -> float:
    sa = set(a); sb = set(b)
    if not sa and not sb: return 1.0
    if not sa or not sb: return 0.0
    inter = len(sa & sb)
    union = len(sa | sb)
    return inter / union

# ---------------------- CLI ----------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """clonelens — detect ABI near-clones & forks offline."""
    pass

def _expand_paths(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        g = glob.glob(p)
        if g:
            out.extend(g)
        elif os.path.isfile(p):
            out.append(p)
    return out

@cli.command("scan")
@click.argument("abi_paths", nargs=-1)
@click.option("--pretty", is_flag=True, help="Human-readable summary for each ABI.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON of per-contract fingerprints.")
def scan_cmd(abi_paths, pretty, json_out):
    """Load ABIs and print each contract's fingerprint & selectors."""
    files = _expand_paths(list(abi_paths))
    if not files:
        raise click.ClickException("No ABI files found.")
    views = [extract_contract_view(p) for p in files]

    if pretty:
        for v in views:
            click.echo(f"== {v.file} ==")
            click.echo(f"  simhash64: 0x{v.simhash64:016x}")
            click.echo(f"  selectors: {len(v.selectors)} unique")
            click.echo("  top functions:")
            for s in v.functions[:8]:
                click.echo(f"    - {s}")
            if len(v.functions) > 8:
                click.echo(f"    … +{len(v.functions)-8} more")
            click.echo("")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([{
                "file": v.file,
                "name_hint": v.name_hint,
                "simhash64": f"0x{v.simhash64:016x}",
                "selectors": v.selectors,
                "functions": v.functions,
                "events": v.events
            } for v in views], f, indent=2)
        click.echo(f"Wrote JSON: {json_out}")

@cli.command("match")
@click.argument("abi_paths", nargs=-1)
@click.option("--top", type=int, default=20, show_default=True, help="How many top pairs to show/save.")
@click.option("--pretty", is_flag=True, help="Human-readable ranked pairs.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON pairs.")
@click.option("--csv", "csv_out", type=click.Path(writable=True), default=None, help="Write CSV pairs.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge for the closest pair.")
def match_cmd(abi_paths, top, pretty, json_out, csv_out, svg_out):
    """Compare all ABIs and rank near-clone pairs by combined score (SimHash + selector Jaccard)."""
    files = _expand_paths(list(abi_paths))
    if len(files) < 2:
        raise click.ClickException("Provide at least two ABI files or a glob that matches 2+ files.")
    views = [extract_contract_view(p) for p in files]

    pairs: List[PairReport] = []
    for i in range(len(views)):
        for j in range(i+1, len(views)):
            a = views[i]; b = views[j]
            sim = simhash_similarity(a.simhash64, b.simhash64)        # 0..1
            jac = jaccard(a.selectors, b.selectors)                   # 0..1
            score = 0.6*sim + 0.4*jac                                 # weighted blend
            common = sorted(set(a.selectors) & set(b.selectors))
            pairs.append(PairReport(
                a=a.file, b=b.file, a_name=a.name_hint, b_name=b.name_hint,
                simhash_sim=sim, selector_jaccard=jac, score=score,
                common_selectors=common, only_a=max(0, len(a.selectors)-len(common)), only_b=max(0, len(b.selectors)-len(common))
            ))

    pairs.sort(key=lambda p: (-p.score, -p.selector_jaccard, -p.simhash_sim))
    top_pairs = pairs[:max(1, top)]

    if pretty:
        click.echo(f"clonelens — top {len(top_pairs)} near-clone pairs")
        for p in top_pairs:
            click.echo(f"  {p.a}  ↔  {p.b}")
            click.echo(f"     score={p.score:.3f}  simhash={p.simhash_sim:.3f}  selectors={p.selector_jaccard:.3f}  common={len(p.common_selectors)}")
        if not top_pairs:
            click.echo("  (no pairs)")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump([asdict(p) for p in top_pairs], f, indent=2)
        click.echo(f"Wrote JSON pairs: {json_out}")

    if csv_out:
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["a","b","score","simhash_sim","selector_jaccard","common_selectors","only_a","only_b"])
            for p in top_pairs:
                w.writerow([p.a, p.b, f"{p.score:.3f}", f"{p.simhash_sim:.3f}", f"{p.selector_jaccard:.3f}", len(p.common_selectors), p.only_a, p.only_b])
        click.echo(f"Wrote CSV pairs: {csv_out}")

    if svg_out:
        if top_pairs:
            best = top_pairs[0]
            # Green if high similarity, amber medium, red low
            c = "#3fb950" if best.score >= 0.85 else "#d29922" if best.score >= 0.6 else "#f85149"
            svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="800" height="48" role="img" aria-label="clonelens">
  <rect width="800" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    clonelens: {best.a} ↔ {best.b}  score {best.score:.3f}
  </text>
  <circle cx="775" cy="24" r="6" fill="{c}"/>
</svg>"""
            with open(svg_out, "w", encoding="utf-8") as f:
                f.write(svg)
            click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or csv_out or svg_out):
        click.echo(json.dumps([asdict(p) for p in top_pairs], indent=2))

if __name__ == "__main__":
    cli()
