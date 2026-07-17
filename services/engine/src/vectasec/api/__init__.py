"""The engine's HTTP surface.

Deliberately thin: the console reads inventory/findings straight from Supabase under RLS,
so nothing here lists things. What lives here is what RLS cannot do — actions that need an
actor, an authorization decision, and an audit row — plus scan orchestration.

The app is not constructed at import time of this package; import `vectasec.api.main`.
"""
