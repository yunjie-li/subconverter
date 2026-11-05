from copy import deepcopy
import unittest
from substore_config import ensure_operation_ids


class OperationIdsTest(unittest.TestCase):
    def test_frontend_lookup_and_save_keep_each_operations_own_arguments(self):
        process = [
            {'type': 'Quick Setting Operator', 'args': {'udp': 'ENABLED'}},
            {'type': 'Regex Filter', 'args': {'regex': ['quota'], 'keep': False}, 'customName': 'exclude quota'},
            {'type': 'Regex Rename Operator', 'args': [{'expr': '^', 'now': '[AI] '}]},
        ]
        original = deepcopy(process)
        # Sub-Store's editor resolves each card using process.find(item.id === id).
        self.assertNotEqual(next(x for x in process if x.get('id') == process[1].get('id'))['args'], process[1]['args'])
        fixed = ensure_operation_ids(process)
        self.assertEqual(process, original)
        self.assertEqual(len({item['id'] for item in fixed}), len(fixed))
        for item in fixed:
            looked_up = next(x for x in fixed if x['id'] == item['id'])
            self.assertEqual(looked_up['type'], item['type'])
            self.assertEqual(looked_up['args'], item['args'])
        self.assertEqual(ensure_operation_ids(fixed), fixed)

    def test_preserves_existing_ids_and_replaces_missing_or_duplicate_ids(self):
        source = [{'id': 'existing', 'type': 'a'}, {'id': 'existing', 'type': 'b'}, {'id': '', 'type': 'c'}, {'type': 'd'}]
        fixed = ensure_operation_ids(source)
        self.assertEqual(fixed[0]['id'], 'existing')
        self.assertEqual(len({item['id'] for item in fixed}), 4)


if __name__ == '__main__': unittest.main()
