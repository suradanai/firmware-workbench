# Firmware Workbench (Extended + Per-Segment Patching + Diff Viewer + Multi-Segment AI)
import sys, os, subprocess, threading, hashlib, shutil, tempfile, random, datetime, yaml, difflib
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QFileDialog, QLabel, QHBoxLayout, QMessageBox,
    QTabWidget, QLineEdit, QCheckBox, QGroupBox, QFormLayout, QListWidget,
    QListWidgetItem, QComboBox, QSplitter, QSizePolicy
)
from PySide6.QtCore import Qt, Signal, QObject, QTimer, QThread
from passlib.hash import sha512_crypt

from fmk_integration import (
    locate_fmk, extract_firmware, build_firmware, extract_multisquash,
    build_multisquash, install_ipk, remove_ipk, postprocess_linksys_footer,
    detect_linksys_candidate, compute_original_rootfs_span,
    estimate_squashfs_size, FMKError
)
from patch_utils import (
    patch_root_password, patch_services, PatchError
)

# ---------------- Utility ----------------
def sha256sum(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

def md5sum(path):
    h=hashlib.md5()
    with open(path,"rb") as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

def get_entropy(path, sample_size=65536, samples=4):
    import math
    size = os.path.getsize(path)
    ent=[]
    with open(path,"rb") as f:
        for _ in range(samples):
            if size>sample_size:
                f.seek(random.randint(0,size-sample_size))
            else:
                f.seek(0)
            data=f.read(sample_size)
            if not data: break
            freq=[0]*256
            for b in data: freq[b]+=1
            e=-sum((c/len(data))*math.log2(c/len(data)) for c in freq if c)
            ent.append(e)
    if not ent: return "-"
    return f"min={min(ent):.3f}, max={max(ent):.3f}, avg={sum(ent)/len(ent):.3f}"

# ---------------- Firmware Analysis ----------------
def analyze_firmware_detailed(fw_path, rootfs_offset, rootfs_size, log_func):
    findings = []
    try:
        log_func(">> วิเคราะห์ boot delay ...")
        with open(fw_path, "rb") as f:
            f.seek(0x100)
            bootdelay_byte = f.read(1)
            if bootdelay_byte:
                bootdelay = bootdelay_byte[0]
                if bootdelay == 0:
                    findings.append("Boot delay = 0 วินาที (ไม่มี delay)")
                elif bootdelay > 9:
                    findings.append(f"Boot delay {bootdelay} วินาที (ยาวผิดปกติ)")
                else:
                    findings.append(f"Boot delay = {bootdelay} วินาที")
    except Exception as e:
        findings.append(f"อ่าน boot delay ผิดพลาด: {e}")

    tmpdir = tempfile.mkdtemp(prefix="fw-rootfs-")
    try:
        rootfs_bin = os.path.join(tmpdir, "rootfs.bin")
        with open(fw_path, "rb") as f:
            f.seek(rootfs_offset)
            chunk = f.read(rootfs_size)
            with open(rootfs_bin, "wb") as o:
                o.write(chunk)
        unsquash_dir = os.path.join(tmpdir, "unsquash")
        os.makedirs(unsquash_dir)
        try:
            subprocess.check_output(
                ["unsquashfs", "-d", unsquash_dir, rootfs_bin],
                stderr=subprocess.STDOUT, timeout=45
            )
            # inittab
            inittab = os.path.join(unsquash_dir,"etc","inittab")
            if os.path.isfile(inittab):
                with open(inittab,"r",encoding="utf-8",errors="ignore") as f:
                    txt=f.read()
                if "getty" in txt and "ttyS" in txt:
                    findings.append("serial shell (getty) อาจเปิดใช้งาน")
                else:
                    findings.append("ไม่พบ getty serial shell")
            # inetd services
            inetd = os.path.join(unsquash_dir,"etc","inetd.conf")
            if os.path.isfile(inetd):
                data=open(inetd,"r",encoding="utf-8",errors="ignore").read()
                findings.append("Telnet enabled" if "telnet" in data else "Telnet disabled")
                findings.append("FTP enabled" if "ftp" in data else "FTP disabled")
            # users
            passwd = os.path.join(unsquash_dir,"etc","passwd")
            if os.path.isfile(passwd):
                users=[line.split(":")[0] for line in open(passwd,"r",encoding="utf-8",errors="ignore") if ":" in line]
                findings.append("Users: " + ", ".join(users))
            shadow = os.path.join(unsquash_dir,"etc","shadow")
            if os.path.isfile(shadow):
                for line in open(shadow,"r",encoding="utf-8",errors="ignore"):
                    if line.startswith("root:"):
                        parts=line.split(":")
                        if parts[1] in ("!","*",""):
                            findings.append("root ไม่มีรหัส / ถูกล็อค")
                        else:
                            findings.append("root มี hash password")
        except Exception as e:
            findings.append(f"แตก rootfs ไม่สำเร็จ: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    findings.append(f"Entropy firmware: {get_entropy(fw_path)}")
    return findings

# ---------------- AI Workers ----------------
class AIWorker(QObject):
    finished = Signal(list)
    error = Signal(str)
    log = Signal(str)
    def __init__(self, fw_path, offset, size):
        super().__init__()
        self.fw_path=fw_path; self.offset=offset; self.size=size
    def run(self):
        try:
            res = analyze_firmware_detailed(self.fw_path,self.offset,self.size,self.log.emit)
            self.finished.emit(res)
        except Exception as e:
            import traceback
            self.error.emit(traceback.format_exc())

class MultiSegmentAIWorker(QObject):
    progress = Signal(str)
    segment_done = Signal(str, list)
    all_done = Signal(dict)
    error = Signal(str)
    def __init__(self, fw_path, segments_meta):
        super().__init__()
        self.fw_path=fw_path
        # segments_meta: list of (segment_name, meta)
        self.segments_meta = segments_meta
        self.stop_flag=False
    def run(self):
        results={}
        try:
            for name, meta in self.segments_meta:
                if self.stop_flag: break
                fs_offset=meta.get("FS_OFFSET")
                footer_off=meta.get("FOOTER_OFFSET", meta.get("FW_SIZE",0))
                rootfs_size = footer_off - fs_offset - meta.get("FOOTER_SIZE",0) if fs_offset else 0
                if not fs_offset or rootfs_size<=0:
                    self.progress.emit(f"[AI ALL] ข้าม {name} (offset/size ไม่ถูกต้อง)")
                    self.segment_done.emit(name, ["Cannot compute rootfs"])
                    continue
                self.progress.emit(f"[AI ALL] วิเคราะห์ {name} offset=0x{fs_offset:X} size={rootfs_size}")
                res = analyze_firmware_detailed(self.fw_path, fs_offset, rootfs_size, self.progress.emit)
                results[name]=res
                self.segment_done.emit(name,res)
            self.all_done.emit(results)
        except Exception as e:
            import traceback
            self.error.emit(traceback.format_exc())

# ---------------- Diff Utilities ----------------
def snapshot_rootfs(rootfs_dir):
    """
    Create snapshot directory rootfs_original beside rootfs if not exists.
    Potentially large (duplicates data). For production you may want rsync + hardlinks or hashing.
    """
    orig = os.path.join(os.path.dirname(rootfs_dir), "rootfs_original")
    if not os.path.exists(orig):
        shutil.copytree(rootfs_dir, orig, symlinks=True)
    return orig

def list_all_files(root_dir):
    out=[]
    for root,dirs,files in os.walk(root_dir):
        for f in files:
            path=os.path.join(root,f)
            rel=os.path.relpath(path, root_dir)
            out.append(rel)
    return set(out)

def read_text_safely(path, max_bytes=512*1024):
    try:
        if os.path.getsize(path) > max_bytes:
            return None, "File too large for diff view"
        with open(path,"rb") as f:
            data=f.read()
        try:
            return data.decode("utf-8"), None
        except UnicodeDecodeError:
            return None, "Binary / non-UTF8"
    except Exception as e:
        return None, f"Read error: {e}"

def compute_diff(rootfs_original, rootfs_current, rel_path):
    a_path=os.path.join(rootfs_original, rel_path)
    b_path=os.path.join(rootfs_current, rel_path)
    a_text,a_err=read_text_safely(a_path) if os.path.exists(a_path) else ("","(new file)")
    b_text,b_err=read_text_safely(b_path) if os.path.exists(b_path) else ("","(removed)")
    if a_err and not os.path.exists(b_path):
        return [f"(removed, cannot read original: {a_err})"]
    if b_err and not os.path.exists(a_path):
        return [f"(new file, cannot read new: {b_err})"]
    if a_text is None or b_text is None:
        return [f"Binary/Unsupported diff: orig_err={a_err} new_err={b_err}"]
    diff=list(difflib.unified_diff(
        a_text.splitlines(), b_text.splitlines(),
        fromfile="orig/"+rel_path, tofile="new/"+rel_path, lineterm=""
    ))
    if not diff:
        return ["(no textual differences)"]
    return diff

def summarize_changes(rootfs_original, rootfs_current):
    orig_files=list_all_files(rootfs_original) if os.path.exists(rootfs_original) else set()
    cur_files=list_all_files(rootfs_current)
    added=cur_files - orig_files
    removed=orig_files - cur_files
    common=orig_files & cur_files
    modified=[]
    for rel in common:
        a=os.path.join(rootfs_original, rel)
        b=os.path.join(rootfs_current, rel)
        try:
            if os.path.getsize(a)!=os.path.getsize(b) or sha256sum(a)!=sha256sum(b):
                modified.append(rel)
        except FileNotFoundError:
            continue
    return added, removed, modified

# ---------------- MainWindow ----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench (Per-Segment Patch + Diff + Multi-Segment AI)")
        self.resize(1850, 1000)

        self.config=self.load_config()
        self.fw_path=None
        self.fmk_root=locate_fmk(self.config.get("fmk",{}).get("root"))
        self.fmk_workspace=None
        self.fmk_meta={}
        self.multisquash_mode=False
        self.segments=[]
        self.current_segment=None
        self.use_sudo_extract=self.config.get("fmk",{}).get("use_sudo_extract","auto")
        self.use_sudo_build=self.config.get("fmk",{}).get("use_sudo_build","auto")

        os.makedirs("workspaces",exist_ok=True)
        os.makedirs("output",exist_ok=True)

        self.log_emitter=LogEmitter()
        self.log_emitter.log_signal.connect(self.append_log)

        self.tabs=QTabWidget()
        self.setCentralWidget(self.tabs)

        # Log tab
        self.log_view=QTextEdit(); self.log_view.setReadOnly(True)
        log_tab=QWidget(); v=QVBoxLayout(log_tab); v.addWidget(QLabel("System Log")); v.addWidget(self.log_view)
        self.tabs.addTab(log_tab,"Logs")

        # AI (basic) tab
        self.ai_info=QTextEdit(); self.ai_info.setReadOnly(True)
        ai_tab=QWidget(); vai=QVBoxLayout(ai_tab)
        fw_sel=QHBoxLayout()
        self.fw_line=QLineEdit(); self.fw_line.setPlaceholderText("เลือก firmware")
        btn_fw=QPushButton("เลือกไฟล์"); btn_fw.clicked.connect(self.choose_firmware)
        fw_sel.addWidget(self.fw_line); fw_sel.addWidget(btn_fw)
        vai.addLayout(fw_sel)
        self.btn_ai_single=QPushButton("วิเคราะห์ (AI) สำหรับ segment ที่เลือก/เดี่ยว")
        self.btn_ai_single.clicked.connect(self.manual_ai_current)
        self.btn_ai_all=QPushButton("วิเคราะห์ทุก Segment (AI ALL)")
        self.btn_ai_all.clicked.connect(self.ai_all_segments)
        vai.addWidget(self.btn_ai_single)
        vai.addWidget(self.btn_ai_all)
        vai.addWidget(QLabel("ผลวิเคราะห์ AI / รวม"))
        vai.addWidget(self.ai_info)
        self.tabs.addTab(ai_tab,"AI")

        # FMK tab (extract/build + patch)
        self.meta_view=QTextEdit(); self.meta_view.setReadOnly(True)
        fmk_tab=QWidget(); vf=QVBoxLayout(fmk_tab)

        path_layout=QHBoxLayout()
        self.fmk_path_line=QLineEdit(self.fmk_root or ""); self.fmk_path_line.setPlaceholderText("FMK Root")
        btn_fmk=QPushButton("เลือก FMK Root"); btn_fmk.clicked.connect(self.choose_fmk_root)
        btn_reload=QPushButton("Reload"); btn_reload.clicked.connect(self.reload_fmk_root)
        path_layout.addWidget(self.fmk_path_line); path_layout.addWidget(btn_fmk); path_layout.addWidget(btn_reload)
        vf.addLayout(path_layout)

        ws_form_box=QGroupBox("Workspace")
        ws_form=QFormLayout()
        self.ws_name=QLineEdit()
        self.ws_name.setPlaceholderText("ws_"+datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.chk_auto_ai=QCheckBox("Auto วิเคราะห์หลัง Extract")
        self.chk_auto_ai.setChecked(True)
        ws_form.addRow("ชื่อ Workspace:", self.ws_name)
        ws_form.addRow("", self.chk_auto_ai)
        ws_form_box.setLayout(ws_form)
        vf.addWidget(ws_form_box)

        ext_btns=QHBoxLayout()
        self.btn_extract_single=QPushButton("Extract Single")
        self.btn_extract_single.clicked.connect(self.extract_single)
        self.btn_extract_multi=QPushButton("Extract Multi-Squash")
        self.btn_extract_multi.clicked.connect(self.extract_multi)
        ext_btns.addWidget(self.btn_extract_single)
        ext_btns.addWidget(self.btn_extract_multi)
        vf.addLayout(ext_btns)

        self.segment_list=QListWidget()
        self.segment_list.itemSelectionChanged.connect(self.segment_selected)
        vf.addWidget(QLabel("Segments (Multi)"))
        vf.addWidget(self.segment_list)

        build_opts=QHBoxLayout()
        self.chk_nopad=QCheckBox("-nopad")
        self.chk_min=QCheckBox("-min (1MB block)")
        self.chk_linksys=QCheckBox("Linksys Footer Fix")
        build_opts.addWidget(self.chk_nopad); build_opts.addWidget(self.chk_min); build_opts.addWidget(self.chk_linksys)
        vf.addLayout(build_opts)

        # Segment Patch Panel
        patch_box=QGroupBox("Patch Segment Rootfs")
        patch_layout=QFormLayout()
        self.rootpw_edit=QLineEdit(); self.rootpw_edit.setPlaceholderText("รหัส root (เว้นว่าง = ล็อกด้วย !)")
        self.chk_serial=QCheckBox("Enable Serial Getty")
        self.chk_serial.setChecked(True)
        self.chk_telnet=QCheckBox("Enable Telnet")
        self.chk_ftp=QCheckBox("Enable FTP")
        self.btn_patch_segment=QPushButton("Apply Patch to Segment")
        self.btn_patch_segment.clicked.connect(self.patch_current_segment)
        patch_layout.addRow("Root Password:", self.rootpw_edit)
        patch_layout.addRow("", self.chk_serial)
        patch_layout.addRow("", self.chk_telnet)
        patch_layout.addRow("", self.chk_ftp)
        patch_layout.addRow("", self.btn_patch_segment)
        patch_box.setLayout(patch_layout)
        vf.addWidget(patch_box)

        pred_layout=QHBoxLayout()
        self.btn_predict=QPushButton("Predict RootFS Size")
        self.btn_predict.clicked.connect(self.predict_rootfs)
        pred_layout.addWidget(self.btn_predict)
        vf.addLayout(pred_layout)

        build_layout=H=QHBoxLayout()
        self.btn_build=QPushButton("Build")
        self.btn_build.clicked.connect(self.build_firmware)
        build_layout.addWidget(self.btn_build)
        vf.addLayout(build_layout)

        vf.addWidget(QLabel("Metadata"))
        vf.addWidget(self.meta_view)
        self.tabs.addTab(fmk_tab,"FMK / Patch")

        # Diff tab
        diff_tab=QWidget(); vd=QVBoxLayout(diff_tab)
        top_bar=QHBoxLayout()
        self.btn_refresh_diff=QPushButton("Refresh Diff List")
        self.btn_refresh_diff.clicked.connect(self.refresh_diff_list)
        self.btn_export_diff=QPushButton("Export Selected Diff")
        self.btn_export_diff.clicked.connect(self.export_selected_diff)
        top_bar.addWidget(self.btn_refresh_diff)
        top_bar.addWidget(self.btn_export_diff)
        vd.addLayout(top_bar)

        self.diff_files_list=QListWidget()
        self.diff_files_list.itemSelectionChanged.connect(self.show_selected_diff)
        vd.addWidget(QLabel("Changed Files (Added / Removed / Modified)"))
        vd.addWidget(self.diff_files_list)

        self.diff_view=QTextEdit(); self.diff_view.setReadOnly(True)
        vd.addWidget(QLabel("Unified Diff"))
        vd.addWidget(self.diff_view)
        self.tabs.addTab(diff_tab,"Diff Viewer")

        # AI aggregated results store
        self.ai_all_results = {}

        if self.fmk_root:
            self.append_log(f"พบ FMK root: {self.fmk_root}")
        else:
            self.append_log("ยังไม่พบ FMK root")

    # ------------- Config -------------
    def load_config(self):
        if os.path.isfile("config.yaml"):
            try:
                with open("config.yaml","r",encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            except Exception:
                return {}
        return {}

    # ------------- Logging -------------
    def append_log(self,text):
        self.log_view.append(text)
        self.log_view.ensureCursorVisible()

    # ------------- FW selection -------------
    def choose_firmware(self):
        path,_=QFileDialog.getOpenFileName(self,"เลือก Firmware")
        if path:
            self.fw_path=path
            self.fw_line.setText(path)
            self.append_log(f"เลือก firmware: {path}")

    # ------------- FMK root -------------
    def choose_fmk_root(self):
        d=QFileDialog.getExistingDirectory(self,"เลือก FMK Root")
        if d:
            self.fmk_root=d
            self.fmk_path_line.setText(d)
            self.append_log(f"ตั้ง FMK root = {d}")

    def reload_fmk_root(self):
        root=self.fmk_path_line.text().strip()
        if not root or not os.path.isdir(root):
            QMessageBox.warning(self,"FMK","Path ไม่ถูกต้อง")
            return
        self.fmk_root=root
        self.append_log(f"Reload FMK root: {root}")

    # ------------- Workspace -------------
    def workspace_name(self):
        name=self.ws_name.text().strip()
        if not name:
            name="ws_"+datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.ws_name.setText(name)
        return name

    def snapshot_current_segment(self):
        # Determine rootfs path
        if self.multisquash_mode and self.current_segment:
            rootfs_dir=os.path.join(self.current_segment["segment_dir"],"rootfs")
        else:
            if not self.fmk_workspace: return
            rootfs_dir=os.path.join(self.fmk_workspace,"rootfs")
        if os.path.isdir(rootfs_dir):
            snapshot_rootfs(rootfs_dir)

    # ------------- Extract Single -------------
    def extract_single(self):
        if not self.fmk_root or not self.fw_line.text():
            QMessageBox.warning(self,"FMK","ตั้ง FMK root และเลือก firmware ก่อน")
            return
        ws=os.path.join("workspaces", self.workspace_name())
        self.append_log(f"[FMK] Extract Single → {ws}")
        self.multisquash_mode=False
        def worker():
            try:
                meta=extract_firmware(self.fmk_root,self.fw_line.text(),ws,
                                      log_callback=self.log_emitter.log_signal.emit,
                                      use_sudo=self.use_sudo_extract)
                self.fmk_workspace=ws
                self.fmk_meta=meta
                self.segments=[]
                self.current_segment=None
                # snapshot
                self.snapshot_current_segment()
                self.log_emitter.log_signal.emit("[FMK] Extract Single สำเร็จ")
                QTimer.singleShot(0,self.render_meta)
                if self.chk_auto_ai.isChecked():
                    self.ai_current_segment(auto=True)
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR extract: {e}")
        threading.Thread(target=worker, daemon=True).start()

    # ------------- Extract Multi -------------
    def extract_multi(self):
        if not self.fmk_root or not self.fw_line.text():
            QMessageBox.warning(self,"FMK","ตั้ง FMK root และเลือก firmware ก่อน")
            return
        ws=os.path.join("workspaces", self.workspace_name())
        self.append_log(f"[FMK] Extract Multi-Squash → {ws}")
        self.multisquash_mode=True
        def worker():
            try:
                segs=extract_multisquash(self.fmk_root,self.fw_line.text(),ws,
                                         log_callback=self.log_emitter.log_signal.emit)
                self.fmk_workspace=ws
                self.segments=segs
                if segs:
                    self.current_segment=segs[0]
                    self.fmk_meta=segs[0]["meta"]
                # snapshot each segment
                for seg in segs:
                    snap_root=os.path.join(seg["segment_dir"],"rootfs")
                    if os.path.isdir(snap_root):
                        snapshot_rootfs(snap_root)
                self.log_emitter.log_signal.emit(f"[FMK] Extract Multi สำเร็จ (segments={len(segs)})")
                QTimer.singleShot(0,self.render_segments)
                QTimer.singleShot(0,self.render_meta)
                if self.chk_auto_ai.isChecked():
                    self.ai_current_segment(auto=True)
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR multi extract: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def render_segments(self):
        self.segment_list.clear()
        for seg in self.segments:
            it=QListWidgetItem(seg["name"])
            it.setData(Qt.UserRole, seg)
            self.segment_list.addItem(it)
        if self.segments:
            self.segment_list.setCurrentRow(0)

    def segment_selected(self):
        items=self.segment_list.selectedItems()
        if not items: return
        seg=items[0].data(Qt.UserRole)
        self.current_segment=seg
        self.fmk_meta=seg["meta"]
        self.render_meta()

    # ------------- Metadata -------------
    def render_meta(self):
        self.meta_view.clear()
        if not self.fmk_meta:
            self.meta_view.setPlainText("No meta.")
            return
        for k,v in self.fmk_meta.items():
            self.meta_view.append(f"{k} = {v}")
        if detect_linksys_candidate(self.fmk_meta):
            self.meta_view.append("Linksys footer candidate detected.")
            self.chk_linksys.setChecked(True)

    # ------------- AI Single Segment -------------
    def manual_ai_current(self):
        self.ai_current_segment(auto=False)

    def ai_current_segment(self, auto=False):
        if not self.fw_line.text():
            if not auto:
                QMessageBox.warning(self,"AI","ยังไม่ได้เลือก firmware")
            return
        fs_offset=self.fmk_meta.get("FS_OFFSET")
        if fs_offset is None:
            if not auto:
                QMessageBox.warning(self,"AI","ยังไม่มี FS_OFFSET (extract ก่อน)")
            return
        footer_off=self.fmk_meta.get("FOOTER_OFFSET", self.fmk_meta.get("FW_SIZE",0))
        rootfs_size=footer_off - fs_offset - self.fmk_meta.get("FOOTER_SIZE",0)
        if rootfs_size<=0:
            self.append_log("[AI] rootfs size invalid")
            return
        self.run_ai_worker(self.fw_line.text(), fs_offset, rootfs_size)

    def run_ai_worker(self, fw_path, offset, size):
        if hasattr(self,"ai_thread_single") and self.ai_thread_single and self.ai_thread_single.isRunning():
            self.append_log("[AI] งานก่อนหน้ายังไม่เสร็จ")
            return
        self.ai_info.append(f"เริ่ม AI offset=0x{offset:X} size={size}")
        self.ai_thread_single=QThread()
        self.ai_worker=AIWorker(fw_path, offset, size)
        self.ai_worker.moveToThread(self.ai_thread_single)
        self.ai_thread_single.started.connect(self.ai_worker.run)
        self.ai_worker.log.connect(self.append_log)
        self.ai_worker.finished.connect(self.ai_single_done)
        self.ai_worker.error.connect(self.ai_single_error)
        self.ai_worker.finished.connect(self.ai_thread_single.quit)
        self.ai_worker.error.connect(self.ai_thread_single.quit)
        self.ai_thread_single.start()

    def ai_single_done(self, findings):
        self.ai_info.append("=== Segment AI Result ===")
        for line in findings:
            self.ai_info.append(line)

    def ai_single_error(self, msg):
        self.ai_info.append("AI ERROR\n"+msg)

    # ------------- AI All Segments -------------
    def ai_all_segments(self):
        if not self.multisquash_mode or not self.segments:
            QMessageBox.information(self,"AI ALL","ต้องอยู่ในโหมด multi-squash (extract multi) ก่อน")
            return
        if hasattr(self,"ai_thread_all") and self.ai_thread_all and self.ai_thread_all.isRunning():
            self.append_log("[AI ALL] กำลังประมวลผลอยู่")
            return
        seg_meta_pairs=[]
        for seg in self.segments:
            seg_meta_pairs.append((seg["name"], seg["meta"]))
        self.ai_info.append("เริ่มวิเคราะห์ทุก segment ...")
        self.ai_thread_all=QThread()
        self.ai_all_worker=MultiSegmentAIWorker(self.fw_line.text(), seg_meta_pairs)
        self.ai_all_worker.moveToThread(self.ai_thread_all)
        self.ai_thread_all.started.connect(self.ai_all_worker.run)
        self.ai_all_worker.progress.connect(self.append_log)
        self.ai_all_worker.segment_done.connect(self.ai_all_segment_done)
        self.ai_all_worker.all_done.connect(self.ai_all_done)
        self.ai_all_worker.error.connect(self.ai_all_error)
        self.ai_all_worker.all_done.connect(self.ai_thread_all.quit)
        self.ai_all_worker.error.connect(self.ai_thread_all.quit)
        self.ai_thread_all.start()

    def ai_all_segment_done(self, name, findings):
        self.ai_info.append(f"--- {name} ---")
        for line in findings:
            self.ai_info.append(line)

    def ai_all_done(self, results):
        self.ai_all_results=results
        self.ai_info.append("=== รวมเสร็จสิ้น ===")
        # Summary detection (e.g. insecure root)
        risk=[]
        for seg, res in results.items():
            for line in res:
                if any(k in line.lower() for k in ["ไม่มีรหัส","telnet enabled","ftp enabled"]):
                    risk.append(f"[{seg}] {line}")
        if risk:
            self.ai_info.append("*** ความเสี่ยงรวม ***")
            for r in risk:
                self.ai_info.append(r)

    def ai_all_error(self, msg):
        self.ai_info.append("AI ALL ERROR\n"+msg)

    # ------------- Predict RootFS -------------
    def predict_rootfs(self):
        meta=self.fmk_meta
        span=compute_original_rootfs_span(meta)
        if span is None:
            QMessageBox.information(self,"Predict","ไม่สามารถคำนวณ span เดิมได้")
            return
        if self.multisquash_mode and self.current_segment:
            rootfs_dir=os.path.join(self.current_segment["segment_dir"],"rootfs")
        else:
            rootfs_dir=os.path.join(self.fmk_workspace,"rootfs")
        if not os.path.isdir(rootfs_dir):
            QMessageBox.information(self,"Predict","ไม่พบ rootfs directory")
            return
        try:
            predicted=estimate_squashfs_size(rootfs_dir, meta, log_callback=self.log_emitter.log_signal.emit)
        except Exception as e:
            QMessageBox.warning(self,"Predict",f"ประเมินไม่สำเร็จ: {e}")
            return
        free=span - predicted
        msg=(f"Original span: {span} bytes\nPredicted: {predicted} bytes\nRemaining: {free} bytes")
        if free<0:
            QMessageBox.warning(self,"Predict","ขนาดเกินพื้นที่เดิม\n"+msg)
        else:
            QMessageBox.information(self,"Predict",msg)

    # ------------- Build Firmware -------------
    def build_firmware(self):
        if not self.fmk_workspace:
            QMessageBox.warning(self,"FMK","ยังไม่มี workspace")
            return
        nopad=self.chk_nopad.isChecked()
        minblk=self.chk_min.isChecked()
        self.append_log(f"[FMK] Build start multi={self.multisquash_mode}")
        warn=self.pre_build_warning()
        if warn:
            c=QMessageBox.warning(self,"Warning",warn+"\n\nดำเนินการต่อ?",QMessageBox.StandardButton.Yes|QMessageBox.StandardButton.No)
            if c!=QMessageBox.StandardButton.Yes:
                return
        def worker():
            try:
                if self.multisquash_mode:
                    out_fw=build_multisquash(self.fmk_root,self.fmk_workspace,nopad=nopad,minblk=minblk,
                                             log_callback=self.log_emitter.log_signal.emit)
                else:
                    out_fw=build_firmware(self.fmk_root,self.fmk_workspace,nopad=nopad,minblk=minblk,
                                          log_callback=self.log_emitter.log_signal.emit)
                if not out_fw:
                    self.log_emitter.log_signal.emit("[FMK] Build failed (no output file).")
                    return
                final=out_fw
                if self.chk_linksys.isChecked() and detect_linksys_candidate(self.fmk_meta):
                    self.log_emitter.log_signal.emit("[FMK] Linksys footer fix ...")
                    mod=postprocess_linksys_footer(self.fmk_root,out_fw,
                                                   log_callback=self.log_emitter.log_signal.emit)
                    if mod:
                        final=mod
                target=os.path.join("output","rebuilt_"+os.path.basename(self.fw_line.text()))
                shutil.copy2(final,target)
                self.log_emitter.log_signal.emit(f"[FMK] Build OK → {target}")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR build: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def pre_build_warning(self):
        meta=self.fmk_meta
        span=compute_original_rootfs_span(meta)
        if span is None: return None
        if self.multisquash_mode and self.current_segment:
            rootfs_dir=os.path.join(self.current_segment["segment_dir"],"rootfs")
        else:
            rootfs_dir=os.path.join(self.fmk_workspace,"rootfs")
        if not os.path.isdir(rootfs_dir): return None
        try:
            predicted=estimate_squashfs_size(rootfs_dir, meta)
        except Exception:
            return None
        free=span - predicted
        if free<0:
            return f"คาดว่าจะเกินพื้นที่ rootfs เดิม (free={free})"
        if free<65536:
            return f"เหลือพื้นที่น้อย (free={free})"
        return None

    # ------------- Segment Patch (root pw / services) -------------
    def patch_current_segment(self):
        if not self.fmk_workspace:
            QMessageBox.warning(self,"Patch","ยังไม่มี workspace")
            return
        if self.multisquash_mode:
            if not self.current_segment:
                QMessageBox.warning(self,"Patch","ยังไม่ได้เลือก segment")
                return
            rootfs_dir=os.path.join(self.current_segment["segment_dir"],"rootfs")
        else:
            rootfs_dir=os.path.join(self.fmk_workspace,"rootfs")
        if not os.path.isdir(rootfs_dir):
            QMessageBox.warning(self,"Patch","ไม่พบ rootfs directory")
            return
        pw=self.rootpw_edit.text()
        enable_serial=self.chk_serial.isChecked()
        enable_telnet=self.chk_telnet.isChecked()
        enable_ftp=self.chk_ftp.isChecked()

        try:
            if pw is not None:
                patch_root_password(rootfs_dir, pw)
                self.append_log("[Patch] Root password updated")
            acts=patch_services(rootfs_dir, ensure_serial=enable_serial,
                                enable_telnet_flag=enable_telnet,
                                enable_ftp_flag=enable_ftp)
            if acts:
                self.append_log("[Patch] Service actions: "+", ".join(acts))
            QMessageBox.information(self,"Patch","Patch สำเร็จ")
        except PatchError as e:
            QMessageBox.warning(self,"Patch",f"ล้มเหลว: {e}")
        except Exception as e:
            QMessageBox.warning(self,"Patch",f"Error: {e}")
        # After patch we can refresh diff
        self.refresh_diff_list()

    # ------------- Diff Viewer -------------
    def get_rootfs_paths(self):
        if self.multisquash_mode and self.current_segment:
            cur=os.path.join(self.current_segment["segment_dir"],"rootfs")
            orig=os.path.join(self.current_segment["segment_dir"],"rootfs_original")
        else:
            cur=os.path.join(self.fmk_workspace,"rootfs") if self.fmk_workspace else None
            orig=os.path.join(self.fmk_workspace,"rootfs_original") if self.fmk_workspace else None
        return orig, cur

    def refresh_diff_list(self):
        self.diff_files_list.clear()
        orig,cur=self.get_rootfs_paths()
        if not orig or not cur or not os.path.isdir(cur):
            self.diff_view.setPlainText("ไม่มี rootfs / ยังไม่ได้ extract")
            return
        if not os.path.isdir(orig):
            self.diff_view.setPlainText("ไม่พบ snapshot (rootfs_original) – จะสร้างอัตโนมัติ")
            snapshot_rootfs(cur)
            orig=os.path.join(os.path.dirname(cur),"rootfs_original")
        added, removed, modified = summarize_changes(orig, cur)
        for r in sorted(added):
            it=QListWidgetItem(f"[A] {r}")
            it.setData(Qt.UserRole, ("added", r))
            self.diff_files_list.addItem(it)
        for r in sorted(removed):
            it=QListWidgetItem(f"[R] {r}")
            it.setData(Qt.UserRole, ("removed", r))
            self.diff_files_list.addItem(it)
        for r in sorted(modified):
            it=QListWidgetItem(f"[M] {r}")
            it.setData(Qt.UserRole, ("modified", r))
            self.diff_files_list.addItem(it)
        self.diff_view.setPlainText(f"Added: {len(added)} | Removed: {len(removed)} | Modified: {len(modified)}")

    def show_selected_diff(self):
        items=self.diff_files_list.selectedItems()
        if not items:
            return
        change_type, rel=items[0].data(Qt.UserRole)
        orig,cur=self.get_rootfs_paths()
        if not orig or not cur:
            return
        if change_type=="added":
            diff=compute_diff(orig,cur,rel)
        elif change_type=="removed":
            diff=compute_diff(orig,cur,rel)
        else:
            diff=compute_diff(orig,cur,rel)
        self.diff_view.setPlainText("\n".join(diff))

    def export_selected_diff(self):
        items=self.diff_files_list.selectedItems()
        if not items:
            QMessageBox.information(self,"Export","ยังไม่ได้เลือกไฟล์")
            return
        _,rel=items[0].data(Qt.UserRole)
        save_path,_=QFileDialog.getSaveFileName(self,"บันทึก diff",f"{rel.replace('/','_')}.diff","Diff Files (*.diff);;All Files (*)")
        if not save_path:
            return
        orig,cur=self.get_rootfs_paths()
        diff=compute_diff(orig,cur,rel)
        with open(save_path,"w",encoding="utf-8") as f:
            f.write("\n".join(diff))
        QMessageBox.information(self,"Export",f"บันทึก diff ที่ {save_path}")

# ---------------- Support Classes ----------------
class LogEmitter(QObject):
    log_signal=Signal(str)

# ---------------- Main ----------------
if __name__=="__main__":
    app=QApplication(sys.argv)
    w=MainWindow()
    w.show()
    sys.exit(app.exec())