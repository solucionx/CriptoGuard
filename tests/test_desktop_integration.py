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

    def test_updater_uses_explicit_non_silent_restart_flow(self):
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        preload = (ROOT / "src" / "preload.js").read_text(encoding="utf-8")
        renderer = (ROOT / "src" / "renderer.js").read_text(encoding="utf-8")
        self.assertIn("autoUpdater.autoInstallOnAppQuit = false", main)
        self.assertIn("autoUpdater.autoRunAppAfterInstall = true", main)
        self.assertIn("autoUpdater.quitAndInstall(false, true)", main)
        self.assertNotIn("autoUpdater.quitAndInstall(true, true)", main)
        self.assertIn("update-install", main)
        self.assertIn("installUpdate", preload)
        self.assertIn("Instalar e reiniciar", renderer)

    def test_downloaded_update_does_not_force_immediate_shutdown(self):
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        start = main.index("autoUpdater.on('update-downloaded'")
        end = main.index("autoUpdater.on('error'", start)
        downloaded_handler = main[start:end]
        self.assertNotIn("installDownloadedUpdateWhenSafe()", downloaded_handler)
        self.assertIn("updateReadyToInstall = true", downloaded_handler)

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


    def test_engine_uses_onedir_bundle_and_packaging_guard(self):
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        build_engine = (ROOT / "scripts" / "build-engine.ps1").read_text(encoding="utf-8")
        build_installer = (ROOT / "scripts" / "build-installer.ps1").read_text(encoding="utf-8")
        resource = next(item for item in package["build"]["extraResources"] if "crypto_guard_engine" in item.get("from", ""))
        self.assertEqual(resource["from"], "engine/crypto_guard_engine")
        self.assertIn("engine', 'crypto_guard_engine', 'crypto_guard_engine.exe", main)
        self.assertIn('"--onedir"', build_engine)
        self.assertNotIn('"--onefile"', build_engine)
        self.assertIn("PackedEngine", build_installer)


    def test_extreme_mode_passes_installation_protection_to_engine(self):
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        bridge = (ROOT / "python" / "bridge.py").read_text(encoding="utf-8")
        smoke = (ROOT / "scripts" / "smoke-engine.py").read_text(encoding="utf-8")
        self.assertIn("protected_paths", main)
        self.assertIn("process.resourcesPath", main)
        self.assertIn("_protected_roots_from_request", bridge)
        self.assertIn('getattr(sys, "frozen", False)', bridge)
        self.assertIn("advanced_mode", smoke)
        self.assertIn("bundle_manifest", smoke)

    def test_engine_protocol_has_ascii_json_and_recovery_journal(self):
        bridge = (ROOT / "python" / "bridge.py").read_text(encoding="utf-8")
        main = (ROOT / "src" / "main.js").read_text(encoding="utf-8")
        self.assertIn("ensure_ascii=True", bridge)
        self.assertIn('encode("ascii")', bridge)
        self.assertIn("status_file", bridge)
        self.assertIn("engine_interrupted_after_verify", main)
        self.assertIn("crypto-guard-status-", main)
        self.assertIn("PYTHONIOENCODING: 'utf-8'", main)


if __name__ == "__main__":
    unittest.main()
