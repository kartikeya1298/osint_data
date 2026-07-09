"""
Regression tests for bug classes that have actually shipped in this
project and were caught late, by manual audit, instead of automatically.

This is NOT a full test suite -- the ~45 fetch_* functions have no
dependency-injection/mocking seams for isolated unit testing, and that's
not what this file is trying to fix. It targets four specific bug
classes that already cost real debugging time this session:

  1. CSV schema drift (CSV_COLUMNS changed but the on-disk master CSV
     header didn't -- would have corrupted every future append).
  2. Country-substring false positives ("india" matching inside
     "Indiana" -- the exact class of bug caught building the Tavily/
     Telegram country-hint filters).
  3. Dedup version/TTL handling (FILTER_VERSION bump not actually
     forcing re-evaluation -- the bug that orphaned ~70% of
     historically-tracked threats this session).
  4. Location field integrity (a data source's own hosting/origin
     country leaking into 'location' instead of the actual target
     country, or 'Global' for sources with no single target).

Run: python test_regression.py
Extend this file the next time a bug from one of these classes ships,
instead of only fixing it in place.
"""
import csv
import json
import tempfile
import unittest
from pathlib import Path

import military_osint_tool_v2 as m


class TestCsvSchemaConsistency(unittest.TestCase):
    """Would have caught: CSV_COLUMNS gained a 16th column (ai_inference)
    while the on-disk master CSV still had the old 15-column header --
    append_to_master() uses CSV_COLUMNS as DictWriter fieldnames, so any
    append under a stale header corrupts rows (None keys / restkey)."""

    def test_master_csv_header_matches_csv_columns(self):
        path = Path(m.CONFIG["master_csv"])
        if not path.exists():
            self.skipTest("no master CSV on disk yet")
        with open(path, encoding="utf-8-sig", newline="") as f:
            header = next(csv.reader(f))
        self.assertEqual(header, m.CSV_COLUMNS,
            "master CSV header has drifted from CSV_COLUMNS -- appending now "
            "will corrupt rows. Rewrite the file with the current header before "
            "the next run (see how the ai_inference column migration was done).")

    def test_no_rows_have_extra_or_missing_columns(self):
        path = Path(m.CONFIG["master_csv"])
        if not path.exists():
            self.skipTest("no master CSV on disk yet")
        with open(path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                self.assertNotIn(None, row.keys(),
                    f"row {i}: has extra unnamed fields (DictReader restkey) -- "
                    f"more values than header columns")
                for col in m.CSV_COLUMNS:
                    self.assertIn(col, row, f"row {i}: missing column {col!r}")


class TestCountrySubstringFalsePositives(unittest.TestCase):
    """Would have caught: a naive `"india" in text.lower()` check matching
    inside "Indiana" -- caught while building the Tavily/Telegram
    country-hint filters this session, before it shipped. _has_any() is
    the word-boundary-safe fix; this locks that behavior in."""

    def test_india_hint_does_not_match_indiana(self):
        self.assertFalse(m._has_any("a study from the university of indiana", m._COUNTRY_NAME_HINTS["IN"]))

    def test_india_hint_matches_real_india_mentions(self):
        self.assertTrue(m._has_any("indian army base camp near the border", m._COUNTRY_NAME_HINTS["IN"]))

    def test_china_hint_does_not_match_indochina(self):
        self.assertFalse(m._has_any("indochina trade route history", m._COUNTRY_NAME_HINTS["CN"]))

    def test_all_country_hints_are_word_boundary_safe(self):
        # Generic sweep, not just the two specific traps found so far --
        # every hint term embedded inside a longer unrelated word should
        # NOT match, for every country this tool tracks.
        for cc, hints in m._COUNTRY_NAME_HINTS.items():
            for hint in hints:
                decoy = f"xx{hint}yy a completely unrelated sentence"
                self.assertFalse(m._has_any(decoy, (hint,)),
                    f"{cc} hint {hint!r} matched inside an unrelated word ({decoy!r}) -- "
                    f"word-boundary check has regressed")


class TestDedupVersioning(unittest.TestCase):
    """Would have caught: bumping FILTER_VERSION not actually forcing
    re-evaluation of stale dedup entries -- the bug that orphaned ~70%
    of historically-tracked threats this session. The real invalidation
    logic lives in load_seen_threats() (filters by filter_version AND a
    30-day TTL when reading seen_threats_v2.json), not in
    deduplicate_rows() itself (which just checks `tid in seen`) -- these
    tests exercise the actual load path, not that simpler check alone."""

    def _with_temp_dedup_file(self, content: dict):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(content, tmp)
        tmp.close()
        return tmp.name

    def test_stale_filter_version_entry_is_dropped_on_load(self):
        path = self._with_temp_dedup_file({
            "T1-XYZ-abc123": {"ts": m.now_utc(), "filter_version": "0.1-old"}
        })
        orig = m.CONFIG.get("dedup_file")
        try:
            m.CONFIG["dedup_file"] = path
            seen = m.load_seen_threats()
        finally:
            m.CONFIG["dedup_file"] = orig
            Path(path).unlink(missing_ok=True)
        self.assertNotIn("T1-XYZ-abc123", seen,
            "an entry recorded under an old FILTER_VERSION must be dropped on load, "
            "so a filter-logic change actually re-evaluates it instead of leaving it "
            "silently suppressed forever")

    def test_current_filter_version_entry_survives_load(self):
        path = self._with_temp_dedup_file({
            "T1-XYZ-abc123": {"ts": m.now_utc(), "filter_version": m.FILTER_VERSION}
        })
        orig = m.CONFIG.get("dedup_file")
        try:
            m.CONFIG["dedup_file"] = path
            seen = m.load_seen_threats()
        finally:
            m.CONFIG["dedup_file"] = orig
            Path(path).unlink(missing_ok=True)
        self.assertIn("T1-XYZ-abc123", seen,
            "an entry recorded under the CURRENT FILTER_VERSION must survive load, "
            "otherwise every run re-collects everything and dedup does nothing")

    def test_expired_ttl_entry_is_dropped_even_under_current_version(self):
        old_ts = (m.datetime.now(m.timezone.utc) - m.timedelta(days=m._SEEN_TTL_DAYS + 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        path = self._with_temp_dedup_file({
            "T1-XYZ-abc123": {"ts": old_ts, "filter_version": m.FILTER_VERSION}
        })
        orig = m.CONFIG.get("dedup_file")
        try:
            m.CONFIG["dedup_file"] = path
            seen = m.load_seen_threats()
        finally:
            m.CONFIG["dedup_file"] = orig
            Path(path).unlink(missing_ok=True)
        self.assertNotIn("T1-XYZ-abc123", seen,
            f"an entry older than _SEEN_TTL_DAYS ({m._SEEN_TTL_DAYS}) must be dropped "
            f"even under the current FILTER_VERSION")

    def test_deduplicate_rows_skips_only_ids_present_in_seen(self):
        seen = {"T1-XYZ-abc123": {"ts": m.now_utc(), "filter_version": m.FILTER_VERSION}}
        rows = [{"threat_id": "T1-XYZ-abc123"}, {"threat_id": "T1-NEW-def456"}]
        new_rows, dup_count = m.deduplicate_rows(rows, seen)
        self.assertEqual(dup_count, 1)
        self.assertEqual([r["threat_id"] for r in new_rows], ["T1-NEW-def456"])


class TestLocationIntegrity(unittest.TestCase):
    """Would have caught: CISA KEV/Feodo Tracker/OTX location bugs, where
    a data source's own hosting/origin leaked into 'location' instead of
    'Global' (for sources with no single target) or the actual targeted
    country parsed from the finding itself."""

    def test_unknown_domain_is_unknown_not_a_guessed_country(self):
        self.assertEqual(m.domain_to_country("example.com"), "Unknown")

    def test_recognizes_target_country_domains(self):
        self.assertEqual(m.domain_to_country("mod.gov.in"), "India")
        self.assertEqual(m.domain_to_country("mod.gov.pk"), "Pakistan")
        self.assertEqual(m.domain_to_country("subdomain.mod.gov.in"), "India")

    def test_master_csv_has_no_blank_location_field(self):
        # A blank string is a different (worse) bug than "Unknown" -- it
        # was the specific shape of the OTX fix this session (.get(key,
        # default) only applies default when the key is ABSENT, not when
        # present-but-empty).
        path = Path(m.CONFIG["master_csv"])
        if not path.exists():
            self.skipTest("no master CSV on disk yet")
        with open(path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            blanks = [row["threat_id"] for row in reader if row.get("location") == ""]
        self.assertEqual(blanks, [],
            f"{len(blanks)} row(s) have a blank (not 'Unknown') location field: {blanks[:5]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
