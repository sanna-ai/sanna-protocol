"""Sanna protocol reference implementation (ALGORITHM v4, draft 5.1).

Reference-only: a pure-Python 3 stdlib implementation of checks C1-C4
under ALGORITHM v4 draft 5.1. This package is NOT shipped in any SDK
(sanna-repo, sanna-ts). Its purpose is to be the executable oracle that
generates fixtures and that the TypeScript implementation (SAN-880)
must byte-match via the differential harness (diff_harness.py).

See reference/spec/ALGORITHM-v4-c1c5-reference.md for the normative
source. Ticket: SAN-879.
"""
