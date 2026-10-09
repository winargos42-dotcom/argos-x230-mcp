"""Desktop shortcut regression without launching an actual browser."""
from pathlib import Path
import tempfile
import unittest
from argos_x230_mcp import desktop_launcher as desktop


class DesktopLauncherTests(unittest.TestCase):
    def test_install_creates_private_shortcuts(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            (home/"Desktop").mkdir()
            paths=desktop.install_desktop(home,Path("/usr/bin/python3"))
            self.assertEqual(len(paths),2)
            for path in paths:
                content=Path(path).read_text()
                self.assertIn("argos_x230_mcp.tunnel_wizard",content)
                self.assertIn("Terminal=true",content)
                self.assertEqual(Path(path).stat().st_mode & 0o777,0o700)
            self.assertEqual(desktop.install_desktop(home,Path("/usr/bin/python3")),paths)

    def test_refuses_to_replace_different_shortcut(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            target=home/".local/share/applications/argos-x230-tunnel-wizard.desktop"
            target.parent.mkdir(parents=True)
            target.write_text("Important existing launcher")
            with self.assertRaises(FileExistsError):
                desktop.install_desktop(home,Path("/usr/bin/python3"))
            self.assertEqual(target.read_text(),"Important existing launcher")

    def test_rejects_unsafe_path_and_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            home=Path(td)
            with self.assertRaises(ValueError):
                desktop.install_desktop(home,Path("relative/python"))
            real=home/"safe";real.write_text("KEEP")
            target=home/".local/share/applications/argos-x230-tunnel-wizard.desktop"
            target.parent.mkdir(parents=True)
            target.symlink_to(real)
            with self.assertRaises(ValueError):
                desktop.install_desktop(home,Path("/usr/bin/python3"))
            self.assertEqual(real.read_text(),"KEEP")


if __name__=="__main__":
    unittest.main()
