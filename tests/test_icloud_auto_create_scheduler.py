import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from email_providers.icloud_pool import AliasLeaseService, AliasRecord
from icloud_auto_create_scheduler import ICloudAutoCreateScheduler


class ICloudAutoCreateSchedulerTests(unittest.TestCase):
    def test_manual_run_works_while_schedule_is_disabled(self):
        config = {
            "icloud_auto_create_enabled": False,
            "icloud_auto_create_interval_minutes": 60,
            "icloud_auto_create_batch_size": 2,
        }
        completed = threading.Event()

        def create_batch(count, log):
            log(f"creating {count}")
            completed.set()
            return {"created_count": count, "failed_count": 0, "emails": ["a@icloud.com", "b@icloud.com"]}

        scheduler = ICloudAutoCreateScheduler(lambda: config, create_batch)
        scheduler.request_run_now()
        scheduler.tick()

        self.assertTrue(completed.wait(1))
        snapshot = scheduler.snapshot()
        self.assertEqual(snapshot["last_status"], "success")
        self.assertEqual(snapshot["today_total_records"], 2)
        self.assertEqual(len(snapshot["recent_success_records"]), 2)
        self.assertIsNone(snapshot["next_run_at"])

    def test_notify_clamps_schedule_values(self):
        config = {
            "icloud_auto_create_enabled": True,
            "icloud_auto_create_interval_minutes": 99999,
            "icloud_auto_create_batch_size": 0,
        }
        scheduler = ICloudAutoCreateScheduler(lambda: config, lambda count, log: {})

        snapshot = scheduler.notify_schedule_updated()

        self.assertEqual(snapshot["interval_minutes"], 1440)
        self.assertEqual(snapshot["batch_size"], 1)
        self.assertIsNotNone(snapshot["next_run_at"])


class ICloudInventoryCreateTests(unittest.TestCase):
    def test_precreated_alias_remains_free_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            service = AliasLeaseService(
                cookies_raw="session=unit-test",
                inventory_path=str(Path(directory) / "aliases.db"),
                background_replenish=False,
                auto_start_background=False,
            )

            def fake_create(*, log_callback=None, mark_platform=True):
                self.assertFalse(mark_platform)
                return AliasRecord(email="ready@icloud.com", anonymous_id="alias-1")

            service._create_remote_alias = fake_create  # type: ignore[method-assign]
            result = service.create_free_aliases(1)

            self.assertEqual(result["created_count"], 1)
            self.assertEqual(result["emails"], ["ready@icloud.com"])
            self.assertEqual(service.stats()["free"], 1)


if __name__ == "__main__":
    unittest.main()
