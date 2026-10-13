"""Mocked controller orchestration tests, without touching host networking."""
import importlib.util
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, call

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('wg_vpn_public', ROOT / 'src/wg-vpn.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)
EXAMPLE = {
    'homeLAN': {'full_profile': 'wg-homeLAN', 'split_profile': 'wg-homeLAN-split'},
    'workLAB': {'full_profile': 'wg-workLAB', 'split_profile': 'wg-workLAB-split'},
}

class ControllerTests(TestCase):
    @patch.object(cli, 'call')
    @patch.object(cli, 'sites', return_value=EXAMPLE)
    def test_full_delegates_prearming_to_guard(self, _sites, runner):
        self.assertEqual(cli.main(['homeLAN', 'full']), 0)
        self.assertEqual(runner.call_args_list, [call('sudo', '-v'), call('sudo', cli.GUARD, 'start', 'homeLAN')])

    @patch.object(cli, 'active_wireguard_profiles', return_value=set())
    @patch.object(cli, 'full_guard_active', return_value=False)
    @patch.object(cli, 'call')
    @patch.object(cli, 'sites', return_value=EXAMPLE)
    def test_split_checks_guard_before_activation(self, _sites, runner, _guard, _active):
        self.assertEqual(cli.main(['workLAB', 'split']), 0)
        self.assertEqual(runner.call_args_list[-1], call('sudo', 'nmcli', '-w', '35', 'connection', 'up', 'wg-workLAB-split'))

    @patch.object(cli, 'active_wireguard_profiles', return_value={'wg-homeLAN-split'})
    @patch.object(cli, 'full_guard_active', return_value=False)
    @patch.object(cli, 'call')
    @patch.object(cli, 'sites', return_value=EXAMPLE)
    def test_stop_disconnects_selected_split(self, _sites, runner, _guard, _active):
        self.assertEqual(cli.main(['homeLAN', 'stop']), 0)
        self.assertEqual(runner.call_args_list[-1], call('sudo', 'nmcli', '-w', '25', 'connection', 'down', 'wg-homeLAN-split'))

    @patch.object(cli, 'full_guard_active', return_value=True)
    @patch.object(cli, 'call')
    @patch.object(cli, 'sites', return_value=EXAMPLE)
    def test_stop_guarded_full_uses_guard_controller(self, _sites, runner, _guard):
        self.assertEqual(cli.main(['homeLAN', 'stop']), 0)
        self.assertEqual(runner.call_args_list[-1], call('sudo', cli.GUARD, 'stop'))

    @patch.object(cli, 'active_wireguard_profiles', return_value={'wg-workLAB'})
    @patch.object(cli, 'full_guard_active', return_value=False)
    @patch.object(cli, 'call')
    @patch.object(cli, 'sites', return_value=EXAMPLE)
    def test_refuse_split_with_unguarded_full(self, _sites, runner, _guard, _active):
        with self.assertRaisesRegex(RuntimeError, 'full-tunnel profile'):
            cli.main(['homeLAN', 'split'])
        self.assertNotIn(call('sudo', 'nmcli', '-w', '35', 'connection', 'up', 'wg-homeLAN-split'), runner.call_args_list)
