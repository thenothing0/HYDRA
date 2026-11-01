"""Synthetic archive boundary laboratory, stdlib only; not a production extractor.
No external archive or target is read. Tests use tiny generated ZIPs/temp paths.
No claim of TOCTOU resistance, complete archive support or decompression hardening.
"""
import io
from pathlib import Path,PureWindowsPath
import stat,tempfile,unittest,zipfile

def archive(entries):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        for name,value in entries: z.writestr(name,value)
    return stream.getvalue()

def extract_demo(blob,root,budget=1024):
    root=root.resolve(); planned=[]
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        if sum(i.file_size for i in z.infolist())>budget: raise ValueError('expanded budget')
        for entry in z.infolist():
            name=entry.filename
            if name.startswith(('/','\\')) or PureWindowsPath(name).drive: raise ValueError('absolute/platform path')
            if stat.S_ISLNK(entry.external_attr>>16): raise ValueError('link entry')
            dest=(root/name.replace('\\','/')).resolve()
            if not dest.is_relative_to(root): raise ValueError('outside intended root')
            planned.append((entry,dest))
        # Complete the supported entry preflight before the first file write.
        total=0
        for entry,dest in planned:
            if entry.is_dir(): dest.mkdir(parents=True,exist_ok=True); continue
            with z.open(entry) as source:
                data=source.read(budget-total+1)
                total+=len(data)
                if total>budget: raise ValueError('actual byte budget')
            dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(data)

class Checks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.base=Path(self.temp.name); self.root=self.base/'extract'; self.root.mkdir()
        self.sentinel=self.base/'sentinel.txt'; self.sentinel.write_text('unchanged')
    def tearDown(self): self.temp.cleanup()
    def test_normal_archive_control(self):
        extract_demo(archive([('nested/file.txt','fixture')]),self.root)
        self.assertEqual((self.root/'nested/file.txt').read_text(),'fixture')
    def test_traversal_rejected_before_any_entry_write(self):
        with self.assertRaises(ValueError): extract_demo(archive([('allowed.txt','first'),('../sentinel.txt','changed')]),self.root)
        self.assertEqual(self.sentinel.read_text(),'unchanged'); self.assertFalse((self.root/'allowed.txt').exists())
    def test_absolute_and_cross_platform_paths_denied(self):
        for name in ('/outside.txt','C:\\outside.txt','\\\\server\\share\\outside.txt'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError): extract_demo(archive([(name,'fixture')]),self.root)
        self.assertEqual(list(self.root.iterdir()),[])
    def test_symlink_entry_denied(self):
        info=zipfile.ZipInfo('link'); info.create_system=3; info.external_attr=(stat.S_IFLNK|0o777)<<16
        with self.assertRaises(ValueError): extract_demo(archive([(info,'../sentinel.txt')]),self.root)
        self.assertEqual(list(self.root.iterdir()),[])
    def test_expanded_budget_denied_before_write(self):
        with self.assertRaises(ValueError): extract_demo(archive([('large.txt','x'*33)]),self.root,budget=32)
        self.assertEqual(list(self.root.iterdir()),[])

if __name__=='__main__': unittest.main(verbosity=2)
