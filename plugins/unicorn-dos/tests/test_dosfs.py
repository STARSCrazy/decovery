import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent.parent / "decovery-plugin-sdk"))

from decovery_unicorn_dos.dosfs import DosFs, short_name  # noqa: E402
from decovery_unicorn_dos.errors import DosError  # noqa: E402


class DosFsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.c = root / "c"
        self.d = root / "d"
        self.c.mkdir()
        (self.d / "binw").mkdir(parents=True)
        (self.d / "binw" / "wcc386.exe").write_bytes(b"MZ")
        (self.d / "LongFileName.Header").write_bytes(b"x")
        self.fs = DosFs({"C": self.c, "D": self.d}, {"D"})
        self.addCleanup(self.fs.close_all)

    def code(self, call, *args):
        with self.assertRaises(DosError) as caught:
            call(*args)
        return caught.exception.code

    def test_short_names(self):
        self.assertEqual(short_name("LongFileName.Header"), "LONGFILE.HEA")
        self.assertEqual(short_name("a.c"), "A.C")
        self.assertEqual(short_name(".."), "..")

    def test_host_maps_8_3_and_case(self):
        self.assertEqual(self.fs.host("D:\\BINW\\WCC386.EXE"), self.d / "binw" / "wcc386.exe")
        self.assertEqual(self.fs.host("d:/longfile.hea"), self.d / "LongFileName.Header")
        self.assertEqual(self.fs.host("D:\\BINW\\..\\.\\LONGFILE.HEA"), self.d / "LongFileName.Header")
        self.assertEqual(self.fs.host("NEW.OBJ"), self.c / "NEW.OBJ")  # current drive C:
        self.assertEqual(self.code(self.fs.host, "E:\\X"), 3)

    def test_create_write_read_seek(self):
        h = self.fs.create("C:\\OUT.TXT")
        self.assertEqual(h, 5)
        self.assertEqual(self.fs.write(h, b"hello"), 5)
        self.assertEqual(self.fs.seek(h, 1, 0), 1)
        self.assertEqual(self.fs.seek(h, 0xFFFFFFFF, 1), 0)  # -1 relative
        self.assertEqual(self.code(self.fs.seek, h, 0xFFFFFFFE, 1), 0x19)
        self.assertEqual(self.fs.read(h, 3), b"hel")
        self.fs.close(h)
        self.assertEqual((self.c / "OUT.TXT").read_bytes(), b"hello")
        self.assertEqual(self.code(self.fs.close, h), 6)
        self.assertEqual(self.code(self.fs.create_new, "OUT.TXT"), 80)
        h2 = self.fs.open("out.txt", 0)
        self.assertEqual(h2, 5)
        self.assertEqual(self.code(self.fs.write, h2, b"x"), 5)  # opened for reading

    def test_console_output_and_devices(self):
        self.assertEqual(self.fs.write(1, b"to console"), 10)
        self.assertEqual(self.fs.write(4, b"printer"), 7)
        self.assertEqual(bytes(self.fs.output), b"to console")
        self.assertEqual(self.fs.read(0, 10), b"")
        h = self.fs.open("NUL", 1)
        self.assertEqual(self.fs.write(h, b"gone"), 4)
        self.assertEqual(bytes(self.fs.output), b"to console")

    def test_read_only_drive(self):
        self.assertEqual(self.code(self.fs.create, "D:\\X.TXT"), 5)
        self.assertEqual(self.code(self.fs.open, "D:\\BINW\\WCC386.EXE", 2), 5)
        self.assertEqual(self.code(self.fs.delete, "D:\\BINW\\WCC386.EXE"), 5)
        self.assertEqual(self.fs.attributes("D:\\BINW\\WCC386.EXE"), 0x21)
        self.assertEqual(self.fs.attributes("D:\\BINW"), 0x10)
        self.assertFalse((self.d / "X.TXT").exists())

    def test_missing_file_and_path(self):
        self.assertEqual(self.code(self.fs.open, "C:\\NONE.C", 0), 2)
        self.assertEqual(self.code(self.fs.open, "C:\\NODIR\\NONE.C", 0), 3)
        self.assertEqual(self.code(self.fs.create, "C:\\NODIR\\NEW.C"), 3)
        self.assertEqual(self.code(self.fs.delete, "C:\\NONE.C"), 2)
        self.assertEqual(self.code(self.fs.attributes, "C:\\NONE.C"), 2)

    def test_rename(self):
        (self.c / "A.TXT").write_bytes(b"a")
        (self.c / "B.TXT").write_bytes(b"b")
        self.assertEqual(self.code(self.fs.rename, "A.TXT", "D:\\A.TXT"), 0x11)
        self.assertEqual(self.code(self.fs.rename, "A.TXT", "B.TXT"), 5)
        self.assertEqual(self.code(self.fs.rename, "Z.TXT", "Y.TXT"), 2)
        self.fs.rename("A.TXT", "C.TXT")
        self.assertEqual((self.c / "C.TXT").read_bytes(), b"a")

    def test_find_first_next(self):
        for name in ("B.OBJ", "A.OBJ", "A.C", "LONGNAME1.OBJ"):
            (self.c / name).write_bytes(b"12345")
        (self.c / "SUB.OBJ").mkdir()
        first = self.fs.find_first("C:\\*.OBJ", 0, key=0x1234)
        names = [first.name]
        while True:
            try:
                names.append(self.fs.find_next(0x1234).name)
            except DosError as e:
                self.assertEqual(e.code, 0x12)
                break
        self.assertEqual(names, ["A.OBJ", "B.OBJ", "LONGNAME.OBJ"])
        record = first.dta()
        self.assertEqual(len(record), 43)
        self.assertEqual(record[0x15], 0x20)
        self.assertEqual(int.from_bytes(record[0x1A:0x1E], "little"), 5)
        self.assertEqual(record[0x1E:0x1E + 6], b"A.OBJ\0")
        with_dirs = self.fs.find_first("*.OBJ", 0x10, key=1)
        self.assertEqual(with_dirs.name, "A.OBJ")
        self.assertEqual(self.code(self.fs.find_first, "*.XYZ", 0, 2), 0x12)
        self.assertEqual(self.code(self.fs.find_first, "C:\\NODIR\\*.*", 0, 3), 3)

    def test_getcwd_and_drives(self):
        self.assertEqual(self.fs.getcwd(0), "")
        self.assertEqual(self.fs.getcwd(4), "")
        self.assertEqual(self.code(self.fs.getcwd, 5), 15)
        self.fs.select_drive(3)
        self.assertEqual(self.fs.current, "D")
        self.fs.select_drive(7)  # not mounted: unchanged
        self.assertEqual(self.fs.current, "D")

    def test_handles_reuse_lowest_free(self):
        a = self.fs.create("A.TXT")
        b = self.fs.create("B.TXT")
        self.assertEqual((a, b), (5, 6))
        self.fs.close(a)
        self.assertEqual(self.fs.create("C.TXT"), 5)
        self.fs.close_all()
        self.assertEqual(sorted(self.fs.handles), [0, 1, 2, 3, 4])

    def test_dup_shares_the_file_until_the_last_close(self):
        (self.c / "IN.TXT").write_bytes(b"abcdef")
        h = self.fs.open("IN.TXT", 0)
        copy = self.fs.dup(h)
        self.assertEqual(copy, 6)
        self.assertEqual(self.fs.read(h, 2), b"ab")
        self.assertEqual(self.fs.read(copy, 2), b"cd")  # shared position
        self.fs.close(h)
        self.assertEqual(self.fs.read(copy, 1), b"e")  # still open
        self.fs.force_dup(1, copy)  # closes the file, handle 6 is the console now
        self.assertEqual(self.fs.write(copy, b"x"), 1)
        self.assertEqual(self.fs.output, b"x")
        self.fs.close(copy)
        self.assertEqual(self.fs.write(1, b"y"), 1)  # stdout itself stays
        self.assertEqual(self.code(self.fs.dup, 9), 6)
        self.assertEqual(self.code(self.fs.force_dup, 9, 1), 6)


if __name__ == "__main__":
    unittest.main()
