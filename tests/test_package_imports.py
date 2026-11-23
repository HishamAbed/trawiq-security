"""Basic import verification tests for the trawiq package."""

import importlib
import unittest


class TestPackageImports(unittest.TestCase):
    """Verify that all core trawiq modules can be imported."""

    def test_import_trawiq(self):
        """Verify that the top-level trawiq package can be imported."""
        module = importlib.import_module("trawiq")
        self.assertIsNotNone(module)

    def test_import_subpackages(self):
        """Verify that all core subpackages can be imported."""
        subpackages = [
            "trawiq.capture",
            "trawiq.preprocessing",
            "trawiq.detection",
            "trawiq.ml_engine",
            "trawiq.integration",
        ]
        for subpkg in subpackages:
            with self.subTest(subpackage=subpkg):
                mod = importlib.import_module(subpkg)
                self.assertIsNotNone(mod)


if __name__ == "__main__":
    unittest.main()
