"""Prober module — active credential extraction from exposed AI gateways.

Unlike passive banner extraction, the prober actively sends HTTP requests to
discovered hosts to read configuration/credential endpoints. Two modes:

1. **Unauthenticated reads** — GET public config/key endpoints that some
   instances expose by misconfiguration (e.g. LobeChat ``/api/config`` that
   dumps all env vars, Flowise ``/api/v1/loginmethod`` that leaks OAuth
   secrets, New-API ``/v1/models`` without auth).

2. **Weak-password login → read** — try a small set of default credentials
   (admin/admin, admin/123456, …) against the product's login endpoint, then
   read authenticated config/key endpoints.

No RCE, SSRF, SQL injection, or destructive operations — strictly read-only.

Architecture
------------
- :class:`Prober` (base) — shared HTTP client, retry, key-extraction glue.
- Product adapters (``probers/*.py``) — implement ``identify()`` and
  ``probe()``, each returning a list of :class:`~aipocket.models.Credential`.
- :func:`probe_hosts` — entry point: given hits from FOFA/Shodan, route each
  to its product adapter by fingerprint, run all probes concurrently.
"""

from __future__ import annotations

from .runner import probe_hosts

__all__ = ["probe_hosts"]
