import time
import json
import os
from pathlib import Path
from collections import defaultdict


SCHEDULE_DB_PATH = Path.home() / ".pegasus_nexus" / "schedule.json"


class SmartScheduler:
    def __init__(self, config, error_handler, persistence_brain=None):
        self.config = config
        self.error_handler = error_handler
        self.brain = persistence_brain
        self.schedule_file = SCHEDULE_DB_PATH
        self.schedule_file.parent.mkdir(parents=True, exist_ok=True)
        self.schedule = self._load_schedule()
        self.client_hourly = defaultdict(lambda: defaultdict(int))

    def _load_schedule(self):
        try:
            if self.schedule_file.exists():
                return json.loads(self.schedule_file.read_text())
        except (json.JSONDecodeError, OSError):
            pass
        return {"entries": [], "client_patterns": {}}

    def _save_schedule(self):
        try:
            self.schedule_file.write_text(json.dumps(self.schedule, indent=2))
        except OSError:
            pass

    def record_client_hour(self, bssid):
        hour = time.localtime().tm_hour
        key = bssid.replace(":", "")
        patterns = self.schedule.setdefault("client_patterns", {})
        hour_key = str(hour)
        entry = patterns.setdefault(key, {})
        entry[hour_key] = entry.get(hour_key, 0) + 1
        entry["_last_seen"] = time.time()
        self._save_schedule()

    def get_best_hour(self, bssid):
        key = bssid.replace(":", "")
        patterns = self.schedule.get("client_patterns", {}).get(key, {})
        hour_counts = {int(k): v for k, v in patterns.items() if k != "_last_seen"}
        if not hour_counts:
            return None
        best = max(hour_counts, key=hour_counts.get)
        return {"hour": best, "count": hour_counts[best]}

    def get_best_hours_for_targets(self, targets):
        if not targets:
            return targets
        current_hour = time.localtime().tm_hour
        scored = []
        for t in targets:
            bssid = t.get("bssid", "")
            best = self.get_best_hour(bssid)
            hour_score = 0
            if best:
                dist = abs(best["hour"] - current_hour)
                hour_score = max(0, 1.0 - dist / 12.0)
            t["_hour_score"] = hour_score
            scored.append(t)
        scored.sort(key=lambda x: x.get("_hour_score", 0), reverse=True)
        return scored

    def schedule_target(self, bssid, ssid, priority=5, interval_min=1440):
        now = time.time()
        entries = self.schedule.setdefault("entries", [])
        for e in entries:
            if e["bssid"] == bssid:
                e["priority"] = priority
                e["interval_min"] = interval_min
                e["next_run"] = now + interval_min * 60
                self._save_schedule()
                return e
        entry = {
            "bssid": bssid,
            "ssid": ssid,
            "priority": priority,
            "interval_min": interval_min,
            "next_run": now + interval_min * 60,
            "last_run": 0,
            "created": now,
            "active": True,
        }
        entries.append(entry)
        self._save_schedule()
        return entry

    def get_due_targets(self, limit=10):
        now = time.time()
        entries = self.schedule.get("entries", [])
        due = [
            e for e in entries
            if e.get("active", True) and e.get("next_run", 0) <= now
        ]
        due.sort(key=lambda e: (
            -e.get("priority", 5),
            e.get("next_run", 0),
        ))
        return due[:limit]

    def mark_run(self, bssid):
        now = time.time()
        for e in self.schedule["entries"]:
            if e["bssid"] == bssid:
                e["last_run"] = now
                e["next_run"] = now + e.get("interval_min", 1440) * 60
                break
        self._save_schedule()

    def auto_schedule_uncracked(self, targets):
        added = 0
        for t in targets:
            bssid = t.get("bssid", "")
            ssid = t.get("ssid", "?")
            priority = t.get("success_probability", 0.5) * 10
            if not self._is_scheduled(bssid):
                self.schedule_target(bssid, ssid, priority=int(priority))
                added += 1
        if added:
            print(f"   Scheduled {added} new targets for recurring attack")
        return added

    def _is_scheduled(self, bssid):
        for e in self.schedule.get("entries", []):
            if e["bssid"] == bssid:
                return True
        return False

    def summary(self):
        entries = self.schedule.get("entries", [])
        active = [e for e in entries if e.get("active", True)]
        now = time.time()
        due = [e for e in active if e.get("next_run", 0) <= now]
        patterns = self.schedule.get("client_patterns", {})
        total_patterns = sum(
            1 for v in patterns.values()
            if any(k != "_last_seen" for k in v)
        )

        print(f"\n{'='*50}")
        print(f"⏰ SMART SCHEDULER SUMMARY")
        print(f"{'='*50}")
        print(f"   Scheduled targets: {len(active)}")
        print(f"   Due now:           {len(due)}")
        print(f"   Targets with patterns: {total_patterns}")

        if due:
            print(f"\n   Due targets:")
            for e in due[:5]:
                remaining = int(e.get("next_run", 0) - now)
                print(f"      {e.get('ssid', '?'):<25} "
                      f"prio={e.get('priority', 5)} "
                      f"due={remaining}s ago")
        if active:
            print(f"\n   Next scheduled:")
            upcoming = sorted(active, key=lambda e: e.get("next_run", 0))[:5]
            for e in upcoming:
                next_in = int(e.get("next_run", 0) - now)
                if next_in > 0:
                    print(f"      {e.get('ssid', '?'):<25} "
                          f"in {next_in // 60}m "
                          f"(interval={e.get('interval_min', 1440)}m)")
        print(f"{'='*50}")
