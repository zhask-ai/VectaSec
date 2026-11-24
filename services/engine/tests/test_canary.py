"""Canaries (canary.py). Pinned: the token is never stored (only its hash), an unknown or
revoked token records nothing, only IP / UA / method are stored, the hourly cap stops inserts
and alerts, the first hit in an hour alerts and later ones do not, the alert is one critical
item, a failing integration never raises, and the public URL needs explicit configuration."""
import json

from vectasec import canary


class Cur:
    def __init__(self, canary_row=None, recent=0, integrations=()):
        self.canary_row, self.recent, self.integrations = canary_row, recent, integrations
        self.log, self._one, self._all = [], None, []

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.log.append((s, params))
        self._one, self._all = None, []
        if s.startswith("insert into canaries"):
            self._one = ("canary-1", "2026-11-23T10:00:00+00:00")
        elif s.startswith("select id, tenant_id, name, placed_in from canaries"):
            self._one = self.canary_row
        elif s.startswith("select count(*) from canary_hits"):
            self._one = (self.recent,)
        elif s.startswith("select id::text, type, name, config, creds_ref from integrations"):
            self._all = list(self.integrations)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


ROW = ("canary-1", "tenant-1", "billing decoy", "n8n workflow 'old export'")


def test_mint_stores_only_the_hash(monkeypatch):
    monkeypatch.setenv("VECTASEC_PUBLIC_URL", "https://engine.example.com/")
    cur = Cur()
    out = canary.mint(cur, "tenant-1", "billing decoy", "n8n", None, "user-1")
    token = out["url"].rsplit("/", 1)[1]
    params = cur.log[0][1]
    assert out["url"].startswith("https://engine.example.com/c/") and len(token) >= 30
    assert token not in json.dumps(params), "the token itself must never be written"
    assert params[4] == canary.token_hash(token) and params[5] == token[:6]
    assert len(out["snippets"]) == 3 and all(out["url"] in s["body"] for s in out["snippets"])


def test_no_public_url_means_no_url(monkeypatch):
    monkeypatch.delenv("VECTASEC_PUBLIC_URL", raising=False)
    out = canary.mint(Cur(), "t", "x")
    assert out["url"] is None and out["snippets"] == [] and "VECTASEC_PUBLIC_URL" in out["note"]
    monkeypatch.setenv("VECTASEC_PUBLIC_URL", "javascript:alert(1)")
    assert canary.public_base() is None


def test_unknown_or_revoked_token_records_nothing():
    cur = Cur(canary_row=None)
    assert canary.record_hit(cur, "nope", source_ip="1.2.3.4", user_agent="curl", method="GET") is None
    assert not any(s.startswith(("insert", "update")) for s, _ in cur.log)
    assert "revoked_at is null" in cur.log[0][0]
    assert canary.record_hit(Cur(), "", source_ip=None, user_agent=None, method="GET") is None
    assert canary.record_hit(Cur(), "x" * 500, source_ip=None, user_agent=None, method="GET") is None


def test_hit_stores_ip_ua_method_only_and_first_hit_alerts():
    cur = Cur(ROW, recent=0)
    hit = canary.record_hit(cur, "tok", source_ip="203.0.113.9", user_agent="python-requests/2.32",
                            method="POST", query_len=42)
    insert = next(p for s, p in cur.log if s.startswith("insert into canary_hits"))
    assert insert == ("tenant-1", "canary-1", "203.0.113.9", "python-requests/2.32", "POST", 42)
    assert hit["alert"] is True and any(s.startswith("insert into audit_log") for s, _ in cur.log)
    again = canary.record_hit(Cur(ROW, recent=3), "tok", source_ip="203.0.113.9", user_agent="x", method="GET")
    assert again["alert"] is False and again["capped"] is False


def test_hourly_cap_counts_but_does_not_insert_or_alert():
    cur = Cur(ROW, recent=canary.HITS_PER_HOUR)
    hit = canary.record_hit(cur, "tok", source_ip="1.1.1.1", user_agent="x", method="GET")
    assert hit["capped"] and hit["alert"] is False
    assert not any(s.startswith("insert into canary_hits") for s, _ in cur.log)
    assert any(s.startswith("update canaries set hit_count") for s, _ in cur.log)


def test_alert_is_one_critical_item_and_failures_are_contained(monkeypatch):
    from vectasec import creds
    monkeypatch.setattr(creds, "resolve_secrets", lambda cur, ref: {})
    monkeypatch.setattr(creds, "runtime_config", lambda cfg, sec: cfg)
    hit = {"tenant_id": "t", "canary_id": "c", "name": "decoy", "placed_in": "wiki", "source_ip": "9.9.9.9"}
    ev = canary.alert_event(hit)
    assert len(ev["findings"]) == 1 and ev["findings"][0]["severity"] == "critical"
    assert "9.9.9.9" in ev["findings"][0]["title"] and "wiki" in ev["findings"][0]["title"]
    sent = []

    def deliver(itype, config, event):
        if itype == "teams":
            raise RuntimeError("hook down token=abc123")
        sent.append(itype)
    cur = Cur(integrations=[("i1", "slack", "Sec", {}, None), ("i2", "teams", "Ops", {}, None)])
    out = canary.send_alerts(cur, hit, deliver=deliver)
    assert sent == ["slack"] and [o["status"] for o in out] == ["sent", "failed"]
    assert "abc123" not in json.dumps(out)
