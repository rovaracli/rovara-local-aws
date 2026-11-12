"""Tests for the memory part of perf/measure.py: the parsers, the private-memory choice and the gate verdicts.
Run: python3 perf/test_measure.py   (no boto3, no build, no network)"""
import contextlib, io, json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import measure

STATUS = "Name:\trovara\nVmRSS:\t  95180 kB\nRssAnon:\t  11160 kB\nRssFile:\t  83980 kB\nRssShmem:\t     40 kB\nThreads:\t12\n"
FOOTPRINT = """======================================================================
rovara-local-aws [4242]: 64-bit    Footprint: 61149184 B (16384 bytes per page)
======================================================================
"""


class Parsers(unittest.TestCase):
    def test_status(self):
        self.assertEqual(measure.parse_status(STATUS), {"VmRSS": 95180, "RssAnon": 11160, "RssFile": 83980, "RssShmem": 40})

    def test_status_without_memory_lines(self):
        self.assertIsNone(measure.parse_status("Name:\tx\nThreads:\t1\n"))
        self.assertIsNone(measure.parse_status(""))

    def test_status_bad_number(self):
        self.assertIsNone(measure.parse_status("RssAnon:\t  lots kB\n"))

    def test_footprint_bytes(self):
        self.assertEqual(measure.parse_footprint(FOOTPRINT), 61149184 // 1024)

    def test_footprint_absent(self):
        self.assertIsNone(measure.parse_footprint("no such process"))
        self.assertIsNone(measure.parse_footprint("Footprint: 2112 KB"))  # only bytes are parsed (-f bytes)


class Sample(unittest.TestCase):
    def fake_proc(self, text):
        root = tempfile.mkdtemp()
        os.makedirs(f"{root}/7")
        open(f"{root}/7/status", "w").write(text)
        return root

    def test_linux_private_is_rssanon_and_total_is_vmrss(self):
        s = measure.mem_sample(7, self.fake_proc(STATUS))
        self.assertEqual((s["private_kib"], s["total_kib"]), (11160, 95180))
        self.assertIn("RssAnon", s["source"])

    def test_no_proc_and_not_macos_falls_back_to_total_rss_and_says_so(self):
        saved_platform, saved_rss = sys.platform, measure.rss_kib
        try:
            sys.platform, measure.rss_kib = "linux", lambda pid: 5000
            s = measure.mem_sample(7, tempfile.mkdtemp())
        finally:
            sys.platform, measure.rss_kib = saved_platform, saved_rss
        self.assertEqual((s["private_kib"], s["total_kib"]), (5000, 5000))
        self.assertIn("total RSS", s["source"])


class Verdicts(unittest.TestCase):
    BASE = {"start_s": 0.03, "idle_mib": 11.0, "peak_mib": 25.0, "idle_rss_mib": 93.0, "peak_rss_mib": 126.0,
            "memory_source": "RssAnon (/proc/<pid>/status)", "median_ms": 4.5, "pass": 58, "total": 59}

    def run_main(self, run, extra=()):
        measure.one_run = lambda a, p: run
        out = tempfile.mktemp()
        sys.argv = ["m", "--label", "t", "--cmd", "x", "--python", "x", "--out", out, "--check", *extra]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                measure.main(); code = 0
            except SystemExit as e:
                code = e.code
        return code, json.load(open(out)), buf.getvalue()

    def test_big_total_rss_does_not_fail_when_private_is_small(self):
        code, summary, out = self.run_main(dict(self.BASE, idle_rss_mib=400.0, peak_rss_mib=900.0))
        self.assertEqual(code, 0)
        self.assertEqual(summary["verdict"]["idle_mib"], "pass")
        self.assertEqual(summary["idle_rss_mib"], 400.0)       # recorded next to it
        self.assertIn("information only", out)

    def test_private_idle_over_64_fails(self):
        code, summary, _ = self.run_main(dict(self.BASE, idle_mib=70.0))
        self.assertEqual((code, summary["verdict"]["idle_mib"]), (1, "MISS"))

    def test_private_peak_over_128_fails(self):
        code, summary, _ = self.run_main(dict(self.BASE, peak_mib=130.0))
        self.assertEqual((code, summary["verdict"]["peak_mib"]), (1, "MISS"))

    def test_targets_are_unchanged(self):
        self.assertEqual((measure.TARGETS["idle_mib"], measure.TARGETS["peak_mib"], measure.TARGETS["start_s"]), (64.0, 128.0, 0.5))

    def test_the_json_names_the_memory_source(self):
        _, summary, _ = self.run_main(dict(self.BASE))
        self.assertEqual(summary["memory_source"], "RssAnon (/proc/<pid>/status)")


if __name__ == "__main__":
    unittest.main(verbosity=1)
