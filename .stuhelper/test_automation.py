import importlib.util
import pathlib
import sys
sys.dont_write_bytecode = True
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('automation', pathlib.Path(__file__).with_name('automation.py'))
automation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(automation)


class AutomationTests(unittest.TestCase):
    def test_stable_releases_exclude_prereleases_drafts_and_injection(self):
        releases = [dict(tag_name=name, draft=draft, prerelease=pre) for name, draft, pre in (
            ('v4.20.0', False, False), ('v5.0.0', False, False), ('v6.0.0-rc.1', False, True),
            ('v9.0.0', True, False), ('v99.0.0;echo bad', False, False), ('v05.0.0', False, False))]
        self.assertEqual(automation.newest_stable(releases)['tag_name'], 'v5.0.0')

    def test_missing_skipped_or_failed_checks_never_merge(self):
        for conclusion in ('skipped', 'neutral', 'cancelled', 'failure', None):
            self.assertFalse(automation.checks_pass([
                {'name': 'Go contracts', 'conclusion': 'success'},
                {'name': 'Web contracts', 'conclusion': conclusion}]))
        self.assertFalse(automation.checks_pass([{'name': 'Go contracts', 'conclusion': 'success'}]))
        self.assertTrue(automation.checks_pass([
            {'name': name, 'conclusion': 'success'} for name in automation.REQUIRED_CHECKS]))

    def test_upstream_cannot_replace_or_add_control_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', *args],
                                               cwd=root, stderr=subprocess.DEVNULL, text=True).strip()
            git('init', '-b', 'main')
            (root / '.github/workflows').mkdir(parents=True)
            (root / '.github/workflows/ci.yml').write_text('trusted')
            (root / '.stuhelper').mkdir()
            (root / '.stuhelper/automation.py').write_text('trusted')
            git('add', '.'); git('commit', '-m', 'base')
            base = git('rev-parse', 'HEAD')
            (root / '.github/workflows/ci.yml').write_text('untrusted')
            (root / '.github/workflows/pwn.yml').write_text('untrusted')
            (root / '.stuhelper/automation.py').write_text('untrusted')
            git('add', '.'); git('commit', '-m', 'upstream')
            def local_run(*args, **kwargs):
                with mock.patch('os.getcwd', return_value=str(root)):
                    result = subprocess.run(args, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.assertIn(result.returncode, kwargs.get('allowed', (0,)))
                    return result
            with mock.patch.object(automation, 'run', side_effect=local_run):
                automation.restore_controls(base)
            self.assertEqual((root / '.github/workflows/ci.yml').read_text(), 'trusted')
            self.assertEqual((root / '.stuhelper/automation.py').read_text(), 'trusted')
            self.assertFalse((root / '.github/workflows/pwn.yml').exists())


if __name__ == '__main__':
    unittest.main()
