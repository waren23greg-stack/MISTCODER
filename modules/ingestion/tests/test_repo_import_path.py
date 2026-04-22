"""Regression checks for repository-root imports under pytest."""

import unittest


class TestRepositoryImportPath(unittest.TestCase):
    def test_modules_namespace_importable(self):
        import modules
        import modules.ingestion

        self.assertTrue(hasattr(modules, "__path__"))
        self.assertTrue(hasattr(modules.ingestion, "__path__"))
