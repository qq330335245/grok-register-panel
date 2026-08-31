# -*- coding: utf-8 -*-
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers import icloud_pool as pool
from email_providers.icloud_hme import ICloudHideMyEmailAlias


def _alias(email, anon, note="", active=True, label=""):
    return ICloudHideMyEmailAlias(
        anonymous_id=anon,
        email=email,
        is_active=active,
        raw={},
        label=label,
        note=note,
        forward_to_email="",
    )


class FakeClient:
    def __init__(self, aliases=None):
        self._aliases = list(aliases or [])
        self.update_calls = []
        self.create_calls = []
        self.delete_calls = []
        self.list_calls = 0

    def list_aliases(self):
        self.list_calls += 1
        return list(self._aliases)

    def update_metadata(self, anonymous_id, note=None, label=None):
        self.update_calls.append((anonymous_id, note, label))
        # reflect note into alias list
        for a in self._aliases:
            if a.anonymous_id == anonymous_id:
                object.__setattr__(a, "note", note or "")
                break
        return {"success": True}

    def create_alias(self, label=None, note=None):
        self.create_calls.append((label, note))
        email = f"new{len(self.create_calls)}@icloud.com"
        a = _alias(email, f"nid-{len(self.create_calls)}", note=note or "")
        self._aliases.append(a)
        return a

    def deactivate_alias(self, anonymous_id):
        return None

    def delete_alias(self, anonymous_id):
        self.delete_calls.append(anonymous_id)
        self._aliases = [a for a in self._aliases if a.anonymous_id != anonymous_id]

    def close(self):
        return None


class AliasLeaseServiceTests(unittest.TestCase):
    def setUp(self):
        pool.reset_services_for_tests()

    def tearDown(self):
        pool.reset_services_for_tests()

    def test_second_acquire_uses_inventory_without_list(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.json")
            aliases = [
                _alias("a@icloud.com", "1", note="openai"),
                _alias("b@icloud.com", "2", note="grok"),
                _alias("c@icloud.com", "3", note=""),
            ]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=True,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                )
                l1 = svc.acquire(owner="w1")
                self.assertIn(l1.email, {"a@icloud.com", "c@icloud.com"})
                self.assertEqual(l1.source, "sync")
                self.assertEqual(fake.list_calls, 1)

                l2 = svc.acquire(owner="w2")
                self.assertIn(l2.email, {"a@icloud.com", "c@icloud.com"} - {l1.email})
                self.assertEqual(l2.source, "inventory")
                self.assertEqual(fake.list_calls, 1)

                svc.commit(lease_id=l1.lease_id, email=l1.email)
                self.assertEqual(fake.list_calls, 1)
                expected_anon = "1" if l1.email == "a@icloud.com" else "3"
                self.assertTrue(any(c[0] == expected_anon for c in fake.update_calls))

    def test_async_mark_only_on_commit_not_acquire(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.json")
            aliases = [_alias("free@icloud.com", "9", note="openai", active=True, label="my-original-label")]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=True,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=True,
                    background_replenish=False,
                    auto_start_background=False,
                )
                lease = svc.acquire(owner="w1")
                self.assertEqual(lease.email, "free@icloud.com")
                # acquire must NOT write cloud note
                self.assertEqual(len(fake.update_calls), 0)
                self.assertEqual(svc.flush_marks(timeout=0.2), 0)

                svc.commit(lease_id=lease.lease_id, email=lease.email)
                n = svc.flush_marks(timeout=2)
                self.assertGreaterEqual(n, 1)
                self.assertTrue(any(c[0] == "9" for c in fake.update_calls))
                # label preserved, note gets grok
                anon, note, label = fake.update_calls[-1]
                self.assertEqual(anon, "9")
                self.assertIn("grok", str(note))
                self.assertEqual(label, "my-original-label")

    def test_ensure_capacity_creates_up_to_cycle(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.json")
            aliases = [_alias("used@icloud.com", "1", note="grok")]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=True,
                    coordination_mode="local_fast",
                    create_when_exhausted=True,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                    low_watermark=3,
                    high_watermark=5,
                    create_per_cycle=2,
                )
                counts = svc.ensure_capacity()
                self.assertEqual(len(fake.create_calls), 2)
                self.assertGreaterEqual(counts.get("free", 0), 2)

    def test_ensure_capacity_marks_healthy_inventory_as_checked(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            fake = FakeClient([_alias("free@icloud.com", "1", note="")])
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=False,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=True,
                    auto_start_background=False,
                    low_watermark=1,
                )
                lease = svc.acquire(owner="worker")
                svc.release(lease_id=lease.lease_id, email=lease.email, recycle=True, cooldown=False)
                svc._last_replenish_at = 0.0

                counts = svc.ensure_capacity()

                self.assertGreaterEqual(counts.get("free", 0), 1)
                self.assertGreater(svc._last_replenish_at, 0.0)

    def test_release_recycles_in_local_fast(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.json")
            aliases = [_alias("free@icloud.com", "9", note="openai")]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=True,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                )
                lease = svc.acquire(owner="w1")
                self.assertEqual(lease.email, "free@icloud.com")
                svc.release(lease_id=lease.lease_id, email=lease.email, recycle=True, cooldown=False)
                lease2 = svc.acquire(owner="w2")
                self.assertEqual(lease2.email, "free@icloud.com")
                self.assertEqual(lease2.source, "inventory")
                self.assertEqual(fake.list_calls, 1)

    def test_create_when_exhausted(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.json")
            aliases = [_alias("used@icloud.com", "1", note="grok")]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=True,
                    coordination_mode="local_fast",
                    create_when_exhausted=True,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                )
                lease = svc.acquire(owner="w1")
                self.assertTrue(lease.email.startswith("new"))
                self.assertEqual(lease.source, "created")
                self.assertEqual(len(fake.create_calls), 1)



    def test_json_migrates_to_sqlite_and_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            inv_json = Path(td) / "inv.json"
            inv_json.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "platform": "grok",
                        "last_full_sync_at": 123.0,
                        "aliases": {
                            "old@icloud.com": {
                                "email": "old@icloud.com",
                                "anonymous_id": "a1",
                                "note_tags": ["openai"],
                                "state": "free",
                                "is_active": True,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            fake = FakeClient([_alias("old@icloud.com", "a1", note="openai")])
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=str(inv_json),
                    platform="grok",
                    cloud_mark=False,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                )
                lease = svc.acquire(owner="w1")
                self.assertEqual(lease.email, "old@icloud.com")
                self.assertTrue(Path(svc._db_path()).exists())
                st = svc.stats()
                self.assertEqual(st.get("inventory_backend"), "sqlite")
                self.assertGreaterEqual(st.get("metrics", {}).get("acquire_total", 0), 1)
                self.assertGreaterEqual(st.get("acquire_inventory_hit_rate", 0), 0.0)



    def test_release_failed_register_does_not_keep_platform_tag(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.json")
            aliases = [_alias("free@icloud.com", "9", note="openai")]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=True,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=True,
                    background_replenish=False,
                    auto_start_background=False,
                )
                lease = svc.acquire(owner="w1")
                svc.release(lease_id=lease.lease_id, email=lease.email, recycle=True, cooldown=False)
                self.assertEqual(len(fake.update_calls), 0)
                # can acquire again
                lease2 = svc.acquire(owner="w2")
                self.assertEqual(lease2.email, "free@icloud.com")



    def test_under_threshold_failures_do_not_cooldown(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            aliases = [_alias("a@icloud.com", "1", note="")]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=False,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                    fail_cooldown_sec=100,
                    fail_cooldown_max_sec=1000,
                    fail_cooldown_threshold=3,
                )
                for n in (1, 2):
                    lease = svc.acquire(owner=f"w{n}")
                    self.assertEqual(lease.email, "a@icloud.com")
                    svc.release(
                        lease_id=lease.lease_id,
                        email=lease.email,
                        recycle=True,
                        cooldown=True,
                        reason=f"fail{n}",
                    )
                    counts = svc.stats()
                    self.assertEqual(counts.get("cooling"), 0)
                    self.assertEqual(counts.get("free"), 1)
                # still re-pickable before threshold
                lease = svc.acquire(owner="w3")
                self.assertEqual(lease.email, "a@icloud.com")

    def test_failed_alias_enters_cooldown_after_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            aliases = [
                _alias("a@icloud.com", "1", note=""),
                _alias("b@icloud.com", "2", note=""),
            ]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=False,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                    fail_cooldown_sec=100,
                    fail_cooldown_max_sec=1000,
                    fail_cooldown_threshold=3,
                )
                first = svc.acquire(owner="x1")
                second = svc.acquire(owner="x2")
                self.assertEqual({first.email, second.email}, {"a@icloud.com", "b@icloud.com"})
                by_email = {first.email: first, second.email: second}
                target = by_email["a@icloud.com"]
                hold = by_email["b@icloud.com"]
                svc.release(
                    lease_id=target.lease_id,
                    email=target.email,
                    recycle=True,
                    cooldown=False,
                )

                # only a free while b held; fail a to threshold
                for n in (1, 2, 3):
                    lease = svc.acquire(owner=f"w{n}")
                    self.assertEqual(lease.email, "a@icloud.com")
                    svc.release(
                        lease_id=lease.lease_id,
                        email=lease.email,
                        recycle=True,
                        cooldown=True,
                        reason=f"fail{n}",
                    )
                    counts = svc.stats()
                    if n < 3:
                        self.assertEqual(counts.get("cooling"), 0)
                        self.assertEqual(counts.get("free"), 1)
                    else:
                        self.assertEqual(counts.get("cooling"), 1)
                        self.assertEqual(counts.get("free"), 0)

                svc.release(lease_id=hold.lease_id, email=hold.email, recycle=True, cooldown=False)
                lease2 = svc.acquire(owner="w4")
                self.assertEqual(lease2.email, "b@icloud.com")

    def test_cooldown_expires_and_prefers_lower_fail_count(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            aliases = [
                _alias("a@icloud.com", "1", note=""),
                _alias("b@icloud.com", "2", note=""),
            ]
            fake = FakeClient(aliases)
            now = {"t": 1_000_000.0}

            def fake_now():
                return now["t"]

            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ), patch("email_providers.icloud_pool._now", side_effect=fake_now):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=False,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                    fail_cooldown_sec=30,
                    fail_cooldown_max_sec=300,
                    fail_cooldown_threshold=3,
                )
                first = svc.acquire(owner="x1")
                second = svc.acquire(owner="x2")
                by_email = {first.email: first, second.email: second}
                a_lease = by_email["a@icloud.com"]
                b_lease = by_email["b@icloud.com"]
                svc.release(
                    lease_id=a_lease.lease_id,
                    email=a_lease.email,
                    recycle=True,
                    cooldown=False,
                )
                for n in range(3):
                    lease = svc.acquire(owner=f"a{n}")
                    self.assertEqual(lease.email, "a@icloud.com")
                    svc.release(
                        lease_id=lease.lease_id,
                        email=lease.email,
                        recycle=True,
                        cooldown=True,
                        reason=f"fail{n+1}",
                    )
                svc.release(
                    lease_id=b_lease.lease_id,
                    email=b_lease.email,
                    recycle=True,
                    cooldown=False,
                )
                l2 = svc.acquire(owner="w2")
                self.assertEqual(l2.email, "b@icloud.com")
                svc.release(lease_id=l2.lease_id, email=l2.email, recycle=True, cooldown=False)
                now["t"] += 31
                l3 = svc.acquire(owner="w3")
                self.assertEqual(l3.email, "b@icloud.com")

    def test_pick_free_is_random_not_alphabetical(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            aliases = [
                _alias("a@icloud.com", "1", note=""),
                _alias("b@icloud.com", "2", note=""),
                _alias("c@icloud.com", "3", note=""),
            ]
            fake = FakeClient(aliases)
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value={"x": "1"}
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    platform="grok",
                    cloud_mark=False,
                    coordination_mode="local_fast",
                    create_when_exhausted=False,
                    async_mark=False,
                    background_replenish=False,
                    auto_start_background=False,
                )
                # force inventory filled
                svc.acquire(owner="warmup")
                # release without cooldown so all free again after draining
                # simpler: inspect _pick_free with fixed seed
                with svc._tx() as conn:
                    data = svc._load_unlocked(conn)
                    records = svc._records(data)
                    for rec in records.values():
                        rec.state = pool.STATE_FREE
                        rec.lease_id = ""
                        rec.fail_count = 0
                        rec.cooldown_until = 0.0
                    svc._dump_records(data, records)
                    svc._save_unlocked(data, conn)

                picks = []
                for i in range(30):
                    with patch("email_providers.icloud_pool.random.choice", side_effect=lambda seq: seq[-1]):
                        with svc._tx() as conn:
                            data = svc._load_unlocked(conn)
                            records = svc._records(data)
                            rec = svc._pick_free(records)
                            picks.append(rec.email if rec else None)
                # with choice=last after unsorted dict iteration is nondeterministic,
                # assert helper uses random.choice by mocking return
                with patch("email_providers.icloud_pool.random.choice", return_value=type("R", (), {"email": "b@icloud.com"})()) as m:
                    with svc._tx() as conn:
                        data = svc._load_unlocked(conn)
                        records = svc._records(data)
                        # rebuild real candidates then ensure choice called
                        # call pick on real records
                    # direct unit: build fake records
                recs = {
                    "a@icloud.com": pool.AliasRecord(email="a@icloud.com", state=pool.STATE_FREE),
                    "b@icloud.com": pool.AliasRecord(email="b@icloud.com", state=pool.STATE_FREE),
                    "c@icloud.com": pool.AliasRecord(email="c@icloud.com", state=pool.STATE_FREE),
                }
                chosen = recs["c@icloud.com"]
                with patch("email_providers.icloud_pool.random.choice", return_value=chosen) as m:
                    got = svc._pick_free(recs)
                    self.assertIs(got, chosen)
                    self.assertTrue(m.called)
                    # must not only pass sorted-by-email single element
                    args = m.call_args[0][0]
                    self.assertEqual({r.email for r in args}, {"a@icloud.com", "b@icloud.com", "c@icloud.com"})



class MultiAccountTests(unittest.TestCase):
    def setUp(self):
        pool.reset_services_for_tests()

    def tearDown(self):
        pool.reset_services_for_tests()

    def test_create_and_list_account_column(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            fake = FakeClient()
            cookies = {"X-APPLE-WEBAUTH-USER": "dsid=123"}
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value=cookies
            ), patch(
                "email_providers.icloud_pool.hme.derive_icloud_dsid", return_value="123"
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    auto_start_background=False,
                    background_replenish=False,
                    async_mark=False,
                )
                added = svc.add_account("dummy", name="main")
                self.assertEqual(added["account"]["id"], "123")
                created = svc.create_free_aliases(1, account_ids=["123"])
                self.assertEqual(created["created_count"], 1)
                rows = svc.list_aliases()
                self.assertEqual(rows[0]["account_id"], "123")
                self.assertEqual(rows[0]["account_name"], "main")

    def test_delete_account_removes_aliases(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            fake = FakeClient()
            cookies = {"X-APPLE-WEBAUTH-USER": "dsid=9"}
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value=cookies
            ), patch(
                "email_providers.icloud_pool.hme.derive_icloud_dsid", return_value="9"
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    auto_start_background=False,
                    background_replenish=False,
                    async_mark=False,
                )
                svc.add_account("dummy", name="gone")
                svc.create_free_aliases(1, account_ids=["9"])
                self.assertEqual(svc.stats()["total"], 1)
                result = svc.delete_account("9")
                self.assertEqual(result["removed_aliases"], 1)
                self.assertEqual(svc.list_accounts(), [])
                self.assertEqual(svc.list_aliases(), [])

    def test_delete_registered_respects_keep_last(self):
        with tempfile.TemporaryDirectory() as td:
            inv = str(Path(td) / "inv.db")
            fake = FakeClient()
            cookies = {"x": "1"}
            with patch("email_providers.icloud_pool.hme.ICloudHideMyEmailClient", return_value=fake), patch(
                "email_providers.icloud_pool.hme.parse_icloud_account_cookies", return_value=cookies
            ):
                svc = pool.AliasLeaseService(
                    cookies_raw="dummy",
                    inventory_path=inv,
                    auto_start_background=False,
                    background_replenish=False,
                    async_mark=False,
                )
                now = time.time()
                with svc._tx() as conn:
                    data = svc._load_unlocked(conn)
                    records = svc._records(data)
                    records["old@icloud.com"] = pool.AliasRecord(
                        email="old@icloud.com",
                        anonymous_id="a1",
                        state=pool.STATE_REGISTERED,
                        last_marked_at=now - 1000,
                    )
                    records["new@icloud.com"] = pool.AliasRecord(
                        email="new@icloud.com",
                        anonymous_id="a2",
                        state=pool.STATE_REGISTERED,
                        last_marked_at=now,
                    )
                    svc._dump_records(data, records)
                    svc._save_unlocked(data, conn)
                result = svc.delete_registered_aliases(10, keep_last=1)
                self.assertEqual(result["deleted_count"], 1)
                self.assertEqual(result["emails"], ["old@icloud.com"])
                remaining = {row["email"] for row in svc.list_aliases()}
                self.assertEqual(remaining, {"new@icloud.com"})


if __name__ == "__main__":
    unittest.main()
