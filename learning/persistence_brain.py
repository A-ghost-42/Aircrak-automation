import sqlite3
import json
import time
import os
import threading
from pathlib import Path
from collections import defaultdict


DB_PATH = Path.home() / ".pegasus_nexus" / "brain.db"


class PersistenceBrain:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path or DB_PATH)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path))
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT UNIQUE NOT NULL,
                interface   TEXT,
                mode        TEXT,
                state       TEXT DEFAULT 'active',
                targets_done INTEGER DEFAULT 0,
                targets_total INTEGER DEFAULT 0,
                password_count INTEGER DEFAULT 0,
                progress     TEXT,
                created_at   REAL NOT NULL,
                updated_at   REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS target_profiles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid       TEXT NOT NULL,
                ssid        TEXT,
                vendor      TEXT,
                oui_prefix  TEXT,
                channel     INTEGER,
                encryption  TEXT,
                first_seen  REAL,
                last_seen   REAL,
                seen_count  INTEGER DEFAULT 1,
                best_signal INTEGER,
                avg_signal  REAL,
                client_peak_hour INTEGER,
                client_peak_score REAL DEFAULT 0,
                handshake_ok INTEGER DEFAULT 0,
                handshake_attempts INTEGER DEFAULT 0,
                pmkid_ok    INTEGER DEFAULT 0,
                pmkid_attempts INTEGER DEFAULT 0,
                is_cracked  INTEGER DEFAULT 0,
                cracked_password TEXT,
                UNIQUE(bssid)
            );

            CREATE TABLE IF NOT EXISTS learned_weights (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                category    TEXT NOT NULL,
                key         TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                total_count INTEGER DEFAULT 0,
                weight      REAL DEFAULT 0.5,
                last_used   REAL,
                UNIQUE(category, key)
            );

            CREATE TABLE IF NOT EXISTS password_patterns (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern     TEXT NOT NULL UNIQUE,
                length      INTEGER,
                charset_type TEXT,
                count       INTEGER DEFAULT 1,
                examples    TEXT,
                last_found  REAL
            );

            CREATE TABLE IF NOT EXISTS attack_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid       TEXT,
                ssid        TEXT,
                timestamp   REAL NOT NULL,
                success     INTEGER,
                password    TEXT,
                method      TEXT,
                duration    REAL,
                tested_count INTEGER,
                capture_type TEXT,
                signal      INTEGER,
                snr         REAL,
                errors      TEXT
            );

            CREATE TABLE IF NOT EXISTS tool_health (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_name   TEXT UNIQUE NOT NULL,
                bin_path    TEXT,
                version     TEXT,
                last_check  REAL,
                healthy     INTEGER DEFAULT 1,
                auto_repair INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS schedule (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target_bssid TEXT,
                target_ssid TEXT,
                priority    INTEGER DEFAULT 5,
                interval_min INTEGER DEFAULT 1440,
                next_run    REAL,
                last_run    REAL,
                active      INTEGER DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_target_bssid ON target_profiles(bssid);
            CREATE INDEX IF NOT EXISTS idx_attack_log_ts ON attack_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_learned_cat ON learned_weights(category, weight);
        """)
        conn.commit()

    # ---- Session Management (Persistence) ----

    def save_session(self, session_id, interface, mode, targets_done=0,
                     targets_total=0, password_count=0, progress=None):
        conn = self._get_conn()
        now = time.time()
        conn.execute("""
            INSERT INTO sessions (session_id, interface, mode, state,
                targets_done, targets_total, password_count, progress,
                created_at, updated_at)
            VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                targets_done=excluded.targets_done,
                targets_total=excluded.targets_total,
                password_count=excluded.password_count,
                progress=excluded.progress,
                updated_at=excluded.updated_at
        """, (session_id, interface, mode, targets_done, targets_total,
              password_count, json.dumps(progress) if progress else None,
              now, now))
        conn.commit()

    def load_session(self, session_id):
        conn = self._get_conn()
        r = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if r:
            d = dict(r)
            if d.get("progress"):
                try:
                    d["progress"] = json.loads(d["progress"])
                except (json.JSONDecodeError, TypeError):
                    d["progress"] = None
            return d
        return None

    def list_sessions(self, limit=10):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def close_session(self, session_id, state="completed"):
        conn = self._get_conn()
        conn.execute(
            "UPDATE sessions SET state = ?, updated_at = ? WHERE session_id = ?",
            (state, time.time(), session_id),
        )
        conn.commit()

    # ---- Target Profile (Persistent Intelligence) ----

    def update_target_profile(self, bssid, ssid, channel=None, encryption=None,
                               signal=None, vendor=None, oui_prefix=None):
        conn = self._get_conn()
        now = time.time()
        existing = conn.execute(
            "SELECT * FROM target_profiles WHERE bssid = ?", (bssid,)
        ).fetchone()

        if existing:
            ex = dict(existing)
            signals = [ex.get("avg_signal", signal) or signal,
                       signal] if signal else [ex.get("avg_signal", -100)]
            avg_sig = round(sum(filter(None, signals)) / len(list(filter(None, signals))), 1)
            best = max(ex.get("best_signal", -100) or -100, signal or -100)

            conn.execute("""
                UPDATE target_profiles SET
                    ssid = COALESCE(?, ssid),
                    channel = COALESCE(?, channel),
                    encryption = COALESCE(?, encryption),
                    vendor = COALESCE(?, vendor),
                    oui_prefix = COALESCE(?, oui_prefix),
                    last_seen = ?,
                    seen_count = seen_count + 1,
                    best_signal = ?,
                    avg_signal = ?
                WHERE bssid = ?
            """, (ssid, channel, encryption, vendor, oui_prefix,
                  now, best, avg_sig, bssid))
        else:
            conn.execute("""
                INSERT INTO target_profiles
                    (bssid, ssid, channel, encryption, vendor, oui_prefix,
                     first_seen, last_seen, best_signal, avg_signal)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (bssid, ssid, channel, encryption, vendor, oui_prefix,
                  now, now, signal, signal))
        conn.commit()

    def record_handshake_attempt(self, bssid, success):
        conn = self._get_conn()
        if success:
            conn.execute("""
                UPDATE target_profiles SET handshake_ok = handshake_ok + 1,
                    handshake_attempts = handshake_attempts + 1
                WHERE bssid = ?
            """, (bssid,))
        else:
            conn.execute("""
                UPDATE target_profiles SET handshake_attempts = handshake_attempts + 1
                WHERE bssid = ?
            """, (bssid,))
        conn.commit()

    def record_pmkid_attempt(self, bssid, success):
        conn = self._get_conn()
        if success:
            conn.execute("""
                UPDATE target_profiles SET pmkid_ok = pmkid_ok + 1,
                    pmkid_attempts = pmkid_attempts + 1
                WHERE bssid = ?
            """, (bssid,))
        else:
            conn.execute("""
                UPDATE target_profiles SET pmkid_attempts = pmkid_attempts + 1
                WHERE bssid = ?
            """, (bssid,))
        conn.commit()

    def mark_cracked(self, bssid, password):
        conn = self._get_conn()
        conn.execute("""
            UPDATE target_profiles SET is_cracked = 1, cracked_password = ?
            WHERE bssid = ?
        """, (password, bssid))
        conn.commit()

    def get_target_profile(self, bssid):
        conn = self._get_conn()
        r = conn.execute(
            "SELECT * FROM target_profiles WHERE bssid = ?", (bssid,)
        ).fetchone()
        return dict(r) if r else None

    def get_known_targets(self, limit=50):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM target_profiles ORDER BY last_seen DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_best_targets(self, limit=10):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM target_profiles
            WHERE is_cracked = 0 AND best_signal > -80
            ORDER BY (handshake_ok * 3 + pmkid_ok * 2) DESC,
                     best_signal DESC,
                     seen_count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---- Learned Weights (Persistent ML) ----

    def record_weight(self, category, key, success):
        conn = self._get_conn()
        now = time.time()
        existing = conn.execute(
            "SELECT * FROM learned_weights WHERE category = ? AND key = ?",
            (category, key),
        ).fetchone()

        if existing:
            sc = existing["success_count"] + (1 if success else 0)
            tc = existing["total_count"] + 1
            w = sc / tc if tc > 0 else 0.5
            conn.execute("""
                UPDATE learned_weights SET
                    success_count = ?, total_count = ?,
                    weight = ?, last_used = ?
                WHERE category = ? AND key = ?
            """, (sc, tc, w, now, category, key))
        else:
            w = 1.0 if success else 0.0
            conn.execute("""
                INSERT INTO learned_weights
                    (category, key, success_count, total_count, weight, last_used)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (category, key, 1 if success else 0, 1, w, now))
        conn.commit()

    def get_weight(self, category, key):
        conn = self._get_conn()
        r = conn.execute(
            "SELECT weight, total_count FROM learned_weights WHERE category = ? AND key = ?",
            (category, key),
        ).fetchone()
        if r:
            return {"weight": r["weight"], "samples": r["total_count"]}
        return {"weight": 0.5, "samples": 0}

    def get_top_weights(self, category, limit=10):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM learned_weights
            WHERE category = ? AND total_count >= 3
            ORDER BY weight DESC, total_count DESC
            LIMIT ?
        """, (category, limit)).fetchall()
        return [dict(r) for r in rows]

    # ---- Password Patterns (Persistent Discovery) ----

    def record_cracked_password(self, password):
        conn = self._get_conn()
        now = time.time()
        length = len(password)
        if password.isdigit():
            ctype = "numeric"
        elif password.isalpha():
            ctype = "alpha"
        elif password.isalnum():
            ctype = "alphanumeric"
        else:
            ctype = "complex"

        pattern = f"{length}_{ctype}"

        existing = conn.execute(
            "SELECT * FROM password_patterns WHERE pattern = ?", (pattern,)
        ).fetchone()

        if existing:
            examples = json.loads(existing["examples"] or "[]")
            if password not in examples:
                examples.append(password)
                if len(examples) > 10:
                    examples = examples[-10:]
            conn.execute("""
                UPDATE password_patterns SET
                    count = count + 1,
                    examples = ?,
                    last_found = ?
                WHERE pattern = ?
            """, (json.dumps(examples), now, pattern))
        else:
            conn.execute("""
                INSERT INTO password_patterns
                    (pattern, length, charset_type, count, examples, last_found)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (pattern, length, ctype, json.dumps([password]), now))
        conn.commit()

    def get_top_patterns(self, limit=10):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM password_patterns
            ORDER BY count DESC, last_found DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---- Attack Log ----

    def log_attack(self, bssid, ssid, success, password=None, method=None,
                    duration=None, tested_count=None, capture_type=None,
                    signal=None, snr=None, errors=None):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO attack_log
                (bssid, ssid, timestamp, success, password, method,
                 duration, tested_count, capture_type, signal, snr, errors)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (bssid, ssid, time.time(), 1 if success else 0, password,
              method, duration, tested_count, capture_type, signal,
              snr, json.dumps(errors) if errors else None))
        conn.commit()

    def get_attack_history(self, bssid=None, limit=20):
        conn = self._get_conn()
        if bssid:
            rows = conn.execute("""
                SELECT * FROM attack_log WHERE bssid = ?
                ORDER BY timestamp DESC LIMIT ?
            """, (bssid, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM attack_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self):
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) as c FROM attack_log").fetchone()["c"]
        ok = conn.execute(
            "SELECT COUNT(*) as c FROM attack_log WHERE success = 1"
        ).fetchone()["c"]
        targets = conn.execute(
            "SELECT COUNT(*) as c FROM target_profiles"
        ).fetchone()["c"]
        cracked = conn.execute(
            "SELECT COUNT(*) as c FROM target_profiles WHERE is_cracked = 1"
        ).fetchone()["c"]
        pw_patterns = conn.execute(
            "SELECT COUNT(*) as c FROM password_patterns"
        ).fetchone()["c"]
        return {
            "attacks_total": total,
            "attacks_success": ok,
            "success_rate": round(ok / total, 3) if total > 0 else 0,
            "targets_known": targets,
            "targets_cracked": cracked,
            "password_patterns_discovered": pw_patterns,
        }

    def summarize(self):
        s = self.get_stats()
        print(f"\n{'='*50}")
        print(f"🧠 PERSISTENCE BRAIN SUMMARY")
        print(f"{'='*50}")
        print(f"   Attacks logged:       {s['attacks_total']}")
        print(f"   Success rate:         {s['success_rate']*100:.1f}%")
        print(f"   Known targets:        {s['targets_known']}")
        print(f"   Cracked targets:      {s['targets_cracked']}")
        print(f"   Password patterns:    {s['password_patterns_discovered']}")

        top = self.get_top_weights("ssid_pattern", 5)
        if top:
            print(f"\n   Top learned weights (SSID patterns):")
            for w in top:
                print(f"      {w['key']:<25} {w['weight']:.2f} ({w['total_count']} samples)")

        patterns = self.get_top_patterns(5)
        if patterns:
            print(f"\n   Top password patterns:")
            for p in patterns:
                ex = json.loads(p["examples"] or "[]")
                ex_str = ", ".join(ex[:3])
                print(f"      len={p['length']} {p['charset_type']:<12} x{p['count']}  e.g. {ex_str}")
        print(f"{'='*50}")
        return s
