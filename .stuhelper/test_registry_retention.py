#!/usr/bin/env python3
import datetime
import importlib.util
import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
path = pathlib.Path(__file__).with_name('registry-retention.py')
spec = importlib.util.spec_from_file_location('retention', path)
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


def digest(number):
    return 'sha256:' + f'{number:064x}'


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.receipt = {
            'schemaVersion': 1, 'retentionPolicy': 'two-successful-generations-v1',
            'migrationPolicy': 'backup-restore-rehearsal-required-v1', 'healthVerified': True, 'ledgerRecorded': True,
            'current': {'imageDigest': digest(3), 'componentVersion': 'v4.20.0-stuhelper.3', 'sourceImageName': retention.SOURCE_IMAGE},
            'previous': {'imageDigest': digest(2), 'componentVersion': 'v4.20.0-stuhelper.2', 'sourceImageName': retention.SOURCE_IMAGE},
            'controlPlaneCommit': 'a' * 40, 'migrationEvidenceSHA256': 'b' * 64,
            'updateRequestId': '018f38b6-8156-7cec-8f0d-81612b6ca190', 'deployedAt': self.now.isoformat(),
        }

    def package(self, number, tags=(), later=False):
        return {'id': number, 'name': digest(number),
                'created_at': (self.now + datetime.timedelta(seconds=1 if later else -30)).isoformat(),
                'metadata': {'container': {'tags': list(tags)}}}

    def test_current_previous_and_complete_proof_graph_remain(self):
        values = [self.package(number) for number in range(1, 9)]
        values[5]['metadata']['container']['tags'] = ['sha256-' + digest(2)[7:] + '.sig']
        manifests = {digest(number): {} for number in range(1, 9)}
        manifests[digest(3)] = {'manifests': [{'digest': digest(4)}]}
        manifests[digest(5)] = {'subject': {'digest': digest(3)}}
        manifests[digest(7)] = {'subject': {'digest': digest(1)}}
        keep, remove = retention.retention_plan(retention.SOURCE_IMAGE, self.receipt, values, manifests)
        self.assertEqual(keep, {digest(n) for n in (2, 3, 4, 5, 6)})
        self.assertEqual({item['id'] for item in remove}, {1, 7, 8})

    def test_higher_unpromoted_candidate_and_concurrent_publication_are_preserved(self):
        values = [self.package(2), self.package(3), self.package(4, ['v5.0.0-stuhelper.1']), self.package(5, later=True)]
        manifests = {item['name']: {} for item in values}
        keep, remove = retention.retention_plan(retention.DEPLOY_IMAGE, self.receipt, values, manifests)
        self.assertEqual(keep, set(manifests))
        self.assertFalse(remove)

    def test_legacy_previous_must_remain_in_private_package(self):
        self.receipt['previous'].update(componentVersion='v3.156.2-stuhelper.2', sourceImageName=None)
        values = [self.package(3)]
        manifests = {digest(3): {}}
        self.assertEqual(retention.retention_plan(retention.SOURCE_IMAGE, self.receipt, values, manifests)[1], [])
        with self.assertRaisesRegex(ValueError, 'rollback image is missing'):
            retention.retention_plan(retention.DEPLOY_IMAGE, self.receipt, values, manifests)

    def test_missing_oci_child_prevents_every_deletion(self):
        values = [self.package(1), self.package(2), self.package(3)]
        manifests = {item['name']: {} for item in values}
        manifests[digest(3)] = {'manifests': [{'digest': digest(20)}]}
        with self.assertRaisesRegex(ValueError, 'child or proof is missing'):
            retention.retention_plan(retention.SOURCE_IMAGE, self.receipt, values, manifests)

    def test_unsuccessful_or_wrong_subject_receipts_never_authorize_cleanup(self):
        retention.validate_receipt(self.receipt, digest(3))
        with self.assertRaisesRegex(ValueError, 'discovery pointer'):
            retention.validate_receipt(self.receipt, digest(4))
        self.receipt['ledgerRecorded'] = False
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            retention.validate_receipt(self.receipt, digest(3))

    def test_source_namespace_cannot_be_substituted(self):
        self.receipt['previous']['sourceImageName'] = 'ghcr.io/unrelated/image'
        with self.assertRaisesRegex(ValueError, 'namespace'):
            retention.validate_receipt(self.receipt, digest(3))


if __name__ == '__main__':
    unittest.main()
