import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DesktopIntegrationTests(unittest.TestCase):
    def test_cguard_file_association_is_declared(self):
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        associations = package["build"].get("fileAssociations", [])
        match = next((item for item in associations if item.get("ext") == "cguard"), None)
        self.assertIsNotNone(match)
        self.assertEqual(match.get("icon"), "build/icon.ico")
        self.assertIn("Crypto Guard", match.get("name", ""))

    def test_double_click_open_pipeline_is_wired(self):
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        preload = (ROOT / "src" / "preload.js").read_text(encoding="utf-8")
        renderer = (ROOT / "src" / "renderer.js").read_text(encoding="utf-8")
        self.assertIn("requestSingleInstanceLock", main)
        self.assertIn("second-instance", main)
        self.assertIn("consume-open-files", main)
        self.assertIn("open-cguard-files", main)
        self.assertIn("consumeOpenFiles", preload)
        self.assertIn("onOpenEncryptedFiles", preload)
        self.assertIn("handleExternalEncryptedFiles", renderer)
        self.assertIn("navigateTo('decrypt')", renderer)

    def test_uac_relaunch_bypasses_single_instance_lock(self):
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        self.assertIn("isElevatedRelaunch ? true : app.requestSingleInstanceLock()", main)

    def test_appearance_customization_is_removed(self):
        html = (ROOT / "src" / "index.html").read_text(encoding="utf-8")
        renderer = (ROOT / "src" / "renderer.js").read_text(encoding="utf-8")
        self.assertNotIn('data-view="settings"', html)
        self.assertNotIn('id="settings"', html)
        self.assertNotIn('id="themeDark"', html)
        self.assertNotIn('id="accent"', html)
        self.assertNotIn('cryptoGuardTheme', renderer)
        self.assertNotIn('cryptoGuardAccent', renderer)
        self.assertNotIn('resetAppearance', renderer)



if __name__ == "__main__":
    unittest.main()
