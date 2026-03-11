"""
nonsudo-verify CLI — VAR-Core receipt chain verifier.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from nonsudo_verify.chain import load_ndjson, load_tsa_sidecar
from nonsudo_verify.models import VerifyResult
from nonsudo_verify.key_resolver import key_from_hex, key_from_pem_file, key_from_config, resolve_public_key
from nonsudo_verify.verifier import verify_chain


def _find_ndjson_paths(path: str) -> list[Path]:
    p = Path(path)
    if p.is_file():
        if p.suffix == ".ndjson" or ".ndjson" in p.suffixes:
            return [p]
        return [p]  # allow single file anyway
    if p.is_dir():
        return sorted(p.glob("*.ndjson"))
    return []


@click.command()
@click.argument("receipts_path", type=click.Path(exists=True), required=False)
@click.option("--key", "key_file", type=click.Path(exists=True), help="Ed25519 public key PEM file")
@click.option("--key-hex", "key_hex", help="Raw 32-byte public key as 64 hex chars")
@click.option("--key-from-config", "use_key_from_config", is_flag=True, help="Read public_key from nonsudo.yaml in cwd")
@click.option("--tier", "tiers", multiple=True, type=click.Choice(["L1", "L2", "L3", "L4"]), help="Run only these tiers")
@click.option("--json", "json_output", is_flag=True, help="JSON output")
@click.option("--quiet", is_flag=True, help="PASS/FAIL only")
@click.option("--strict", is_flag=True, help="Exit 2 if any tier is OFFLINE")
@click.option("--conformance", is_flag=True, help="Run all 21 conformance vectors")
def main(
    receipts_path: str | None,
    key_file: str | None,
    key_hex: str | None,
    use_key_from_config: bool,
    tiers: tuple[str, ...],
    json_output: bool,
    quiet: bool,
    strict: bool,
    conformance: bool,
) -> None:
    """VAR-Core receipt chain verifier — reference implementation 2."""
    if conformance:
        _run_conformance(key_hex=key_hex, json_output=json_output, quiet=quiet)
        return
    if not receipts_path:
        click.echo("Error: RECEIPTS_PATH required (or use --conformance)", err=True)
        raise SystemExit(3)
    paths = _find_ndjson_paths(receipts_path)
    if not paths:
        click.echo(f"Error: no NDJSON files found at {receipts_path}", err=True)
        raise SystemExit(3)
    cwd = Path.cwd()
    config_path = cwd / "nonsudo.yaml"
    pub_key = None
    if key_hex:
        pub_key = key_from_hex(key_hex)
    elif key_file:
        pub_key = key_from_pem_file(key_file)
    elif use_key_from_config and config_path.exists():
        pub_key = key_from_config(config_path)
    if pub_key is None and not key_hex and not key_file and not use_key_from_config:
        pub_key = key_from_config(config_path)
    results: list[VerifyResult] = []
    for p in paths:
        receipts = load_ndjson(p)
        tsa = load_tsa_sidecar(p)
        res = verify_chain(
            receipts,
            str(p),
            public_key=pub_key,
            tsa_records=tsa,
        )
        results.append(res)
        if not json_output and not quiet:
            _print_result(res)
    if json_output:
        out = {
            "spec_version": "var/1.0",
            "chains": [
                {
                    "chain_path": r.chain_path,
                    "receipt_count": r.receipt_count,
                    "tiers": {
                        "L1": {"status": r.l1_status, "detail": r.l1_detail},
                        "L2": {"status": r.l2_status, "detail": r.l2_detail},
                        "L3": {"status": r.l3_status, "detail": r.l3_detail},
                        "L4": {"status": r.l4_status, "detail": r.l4_detail},
                    },
                    "result": r.overall,
                }
                for r in results
            ],
            "result": "PASS" if all(r.overall == "PASS" for r in results) else "FAIL",
        }
        click.echo(json.dumps(out, indent=2))
    any_fail = any(r.overall == "FAIL" for r in results)
    any_offline = any(
        r.l1_status == "OFFLINE" or r.l3_status == "OFFLINE"
        for r in results
    )
    if any_fail:
        raise SystemExit(1)
    if strict and any_offline:
        raise SystemExit(2)
    raise SystemExit(0)


def _print_result(r: VerifyResult) -> None:
    console = Console()
    console.print("[bold]nonsudo-verify  ·  VAR-Core v1.0[/bold]")
    console.print(f"Chain: {r.chain_path}")
    console.print(f"Receipts: {r.receipt_count}")
    console.print()
    def tick(s: str) -> str:
        return f"[green]✓[/green] {s}" if s == "PASS" else f"[red]✗[/red] {s}"
    console.print(f"L1  Ed25519 signature verification    {tick(r.l1_status)}  {r.l1_detail or ''}")
    console.print(f"L2  Hash chain integrity              {tick(r.l2_status)}  {r.l2_detail or ''}")
    console.print(f"L3  Timestamp authority               {tick(r.l3_status)}  {r.l3_detail or ''}")
    console.print(f"L4  Terminal outcome completeness     {tick(r.l4_status)}  {r.l4_detail or ''}")
    console.print()
    console.print("────────────────────────────────────────────────────────")
    console.print(f"RESULT   {r.overall}  ·  {r.receipt_count} receipts verified")
    console.print("────────────────────────────────────────────────────────")


def _run_conformance(key_hex: str | None, json_output: bool, quiet: bool) -> None:
    """Run conformance vectors from tests/fixtures/conformance/*.ndjson."""
    test_pub_hex = key_hex or "3b321b74bdcb169f7260c60592bbb63d9b4d629424a0c58aff4640a75f0a2b06"
    pub_key = key_from_hex(test_pub_hex)
    if not pub_key:
        click.echo("Error: invalid --key-hex for conformance", err=True)
        raise SystemExit(3)
    base = Path(__file__).resolve().parent.parent
    fixtures_dir = base / "tests" / "fixtures" / "conformance"
    if not fixtures_dir.exists():
        click.echo("Conformance fixtures not found.", err=True)
        raise SystemExit(3)
    ndjson_files = list(fixtures_dir.glob("*.ndjson"))
    if not ndjson_files:
        click.echo("No *.ndjson in conformance fixtures.", err=True)
        raise SystemExit(3)
    passed = 0
    total = len(ndjson_files)
    for f in sorted(ndjson_files):
        receipts = load_ndjson(f)
        res = verify_chain(receipts, str(f), public_key=pub_key)
        if res.overall == "PASS":
            passed += 1
        elif not quiet:
            click.echo(f"FAIL {f.name}: {res.l1_detail or res.l2_detail or res.l4_detail}")
    if json_output:
        click.echo(json.dumps({"conformance": f"{passed}/{total} PASS", "passed": passed, "total": total}))
    else:
        click.echo(f"Conformance: {passed}/{total} PASS")
    raise SystemExit(0 if passed == total else 1)
