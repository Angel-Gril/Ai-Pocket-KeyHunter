"""Prober module — active credential extraction from exposed AI gateways.

Unlike passive banner extraction, the prober actively sends HTTP requests to
discovered hosts. Capability model (vuln-class nodes):

* **L0 unauth_read** — public config/key GETs (always on).
* **L1 weak_password / idor** — dictionary login + object-level reads.
* **L2 ssrf / sqli** — audited minimal read proofs (every product ships Specs).
* **L3 rce** — whitelist-only minimal execution proof (every product ships Specs).

Gates (Settings / env). Library defaults are conservative; full-sweep deploys
typically enable L1–L3 via ``.env``:

* L1+ require ``intrusive_checks``. ``authorized_probe_scope`` empty = all
  probe-eligible targets; non-empty = exact-origin allowlist.
* L2 also needs ``probe_max_risk >= 2`` and ``probe_ssrf_enabled`` /
  ``probe_sqli_enabled``.
* L3 also needs ``probe_max_risk >= 3`` and ``probe_rce_enabled``.

Only reviewed :class:`~aipocket.prober.capability.ProbeSpec` nodes may issue
requests. Natural-language CVE text is never compiled into payloads.

Architecture
------------
- :class:`Prober` (base) — shared HTTP client, retry, key-extraction glue.
- ``capability/`` — ProbeSpec, RiskPolicy, planner, executor.
- ``engines/`` — per-vuln-class execution loops.
- Product adapters (``probers/*.py``) — ``identify()`` + L0–L3 Spec registration.
- :func:`probe_hosts` — entry point: route DiscoveryTargets → product plan.
"""

from __future__ import annotations

from .runner import probe_hosts

__all__ = ["probe_hosts"]
