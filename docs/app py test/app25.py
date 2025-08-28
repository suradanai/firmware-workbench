# เวอร์ชันเสริม: เพิ่มแท็บ FMK Integration
import sys, os, subprocess, threading, hashlib, shutil, tempfile, random, yaml, datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QFileDialog, QLabel, QComboBox, QHBoxLayout, QMessageBox,
    QTabWidget, QLineEdit, QSpinBox, QCheckBox, QGroupBox, QFormLayout
)
from PySide6.QtCore import Qt, Signal, QObject, QTimer, QThread
from passlib.hash import sha512_crypt

# นำเข้าของเรา
from fmk_integration import (
    locate_fmk, extract_firmware, build_firmware,
    install_ipk, remove_ipk, postprocess_linksys_footer,
    detect_linksys_candidate, FMKError
)

# ========== ฟังก์ชันพื้นฐาน (เดิม) ==========
def sha256sum(path):
    h = hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

def md5sum(path):
    h = hashlib.md5()
    with open(path,"rb") as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

def get_filetype(path):
    try:
        out = subprocess.check_output(["file", path], text=True)
        return out.strip()
    except Exception as e:
        return f"file error: {e}"

# (ลดรายละเอียด analyze_firmware_detailed เพื่อให้ไม่ยาวเกิน – สมมุติใช้โค้ดเดิมคุณวางทับ)
def get_entropy(path, sample_size=65536, samples=4):
    import math
    size = os.path.getsize(path)
    import random
    ent = []
    with open(path,"rb") as f:
        for _ in range(samples):
            if size > sample_size:
                f.seek(random.randint(0,size-sample_size))
            else:
                f.seek(0)
            data = f.read(sample_size)
            if not data: break
            freq=[0]*256
            for b in data: freq[b]+=1
            e = -sum((c/len(data))*math.log2(c/len(data)) for c in freq if c)
            ent.append(e)
    if not ent: return "-"
    return f"min={min(ent):.3f}, max={max(ent):.3f}, avg={sum(ent)/len(ent):.3f}"

# Placeholder ของของเดิม (ควรใช้เวอร์ชันเต็มจากก่อนหน้า)
def analyze_firmware_detailed(fw_path, offset, size, log_func):
    log_func("[AI] (mock) เริ่มวิเคราะห์ ...")
    # คุณสามารถคงของจริงไว้
    return [
        "Boot delay = 1 วินาที (ปกติ)",
        "ไม่พบ Telnet service",
        "ไม่พบ FTP service",
        "User ที่พบในระบบ: root, nobody",
        "Rootfs entropy ปกติ",
    ]

# ========== Signals ==========
class LogEmitter(QObject):
    log_signal = Signal(str)

class AIWorker(QObject):
    finished = Signal(list)
    error = Signal(str)
    log = Signal(str)
    def __init__(self, fw_path, offset, size):
        super().__init__()
        self.fw_path=fw_path; self.offset=offset; self.size=size
    def run(self):
        try:
            findings = analyze_firmware_detailed(self.fw_path, self.offset, self.size, log_func=self.log.emit)
            self.finished.emit(findings)
        except Exception as e:
            import traceback
            self.error.emit(traceback.format_exc())

# ========== MainWindow ==========
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench (with FMK Integration)")
        self.resize(1500, 950)

        # Paths & states
        self.config = self.load_config()
        self.fw_path = None
        self.analysis_result = None
        self.ai_running = False
        self.fmk_root = None
        self.fmk_workspace = None
        self.fmk_meta = {}
        self.use_sudo_extract = self.config.get("fmk",{}).get("use_sudo_extract","auto")
        self.use_sudo_build = self.config.get("fmk",{}).get("use_sudo_build","auto")

        # Default dirs
        os.makedirs("input", exist_ok=True)
        os.makedirs("output", exist_ok=True)
        os.makedirs("workspaces", exist_ok=True)

        # try locate FMK
        self.fmk_root = locate_fmk(self.config.get("fmk",{}).get("root"))
        # GUI
        self.log_emitter = LogEmitter()
        self.log_emitter.log_signal.connect(self.append_log)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.log_panel = QTextEdit(); self.log_panel.setReadOnly(True)
        self.info_panel = QTextEdit(); self.info_panel.setReadOnly(True)

        # Tab: Logs
        log_tab = QWidget()
        v_log = QVBoxLayout(log_tab)
        v_log.addWidget(QLabel("System Log"))
        v_log.addWidget(self.log_panel)
        self.tabs.addTab(log_tab, "Logs")

        # Tab: AI / Basic (ย่อ)
        ai_tab = QWidget()
        v_ai = QVBoxLayout(ai_tab)

        fw_select_layout = QHBoxLayout()
        self.fw_line = QLineEdit(); self.fw_line.setPlaceholderText("เลือกไฟล์ firmware หรือวาง path")
        btn_browse_fw = QPushButton("เลือกไฟล์ Firmware")
        btn_browse_fw.clicked.connect(self.choose_firmware)
        fw_select_layout.addWidget(self.fw_line)
        fw_select_layout.addWidget(btn_browse_fw)
        v_ai.addLayout(fw_select_layout)

        self.btn_run_ai = QPushButton("วิเคราะห์ Firmware (AI)")
        self.btn_run_ai.clicked.connect(self.run_ai_analysis_manual)
        v_ai.addWidget(self.btn_run_ai)
        v_ai.addWidget(QLabel("ผลสรุป / Info"))
        v_ai.addWidget(self.info_panel)

        self.tabs.addTab(ai_tab, "Basic / AI")

        # Tab: FMK
        fmk_tab = QWidget()
        fmk_layout = QVBoxLayout(fmk_tab)

        fmk_path_layout = QHBoxLayout()
        self.fmk_path_line = QLineEdit(self.fmk_root or "")
        self.fmk_path_line.setPlaceholderText("FMK Root (external/firmware_mod_kit)")
        btn_fmk_browse = QPushButton("เลือก FMK Root")
        btn_fmk_browse.clicked.connect(self.choose_fmk_root)
        btn_fmk_reload = QPushButton("Reload FMK")
        btn_fmk_reload.clicked.connect(self.reload_fmk_root)
        fmk_path_layout.addWidget(self.fmk_path_line)
        fmk_path_layout.addWidget(btn_fmk_browse)
        fmk_path_layout.addWidget(btn_fmk_reload)
        fmk_layout.addLayout(fmk_path_layout)

        # Workspace controls
        ws_group = QGroupBox("Workspace (FMK)")
        form_ws = QFormLayout()
        self.ws_name_edit = QLineEdit()
        self.ws_name_edit.setPlaceholderText("ตัวอย่าง: ws_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.chk_auto_analyze = QCheckBox("Auto AI วิเคราะห์หลัง Extract")
        self.chk_auto_analyze.setChecked(True)
        form_ws.addRow("ชื่อ Workspace:", self.ws_name_edit)
        form_ws.addRow("", self.chk_auto_analyze)
        ws_group.setLayout(form_ws)
        fmk_layout.addWidget(ws_group)

        ws_btns = QHBoxLayout()
        self.btn_fmk_extract = QPushButton("Extract (FMK)")
        self.btn_fmk_extract.clicked.connect(self.do_fmk_extract)
        self.btn_fmk_build = QPushButton("Build Firmware (FMK)")
        self.btn_fmk_build.clicked.connect(self.do_fmk_build)
        ws_btns.addWidget(self.btn_fmk_extract)
        ws_btns.addWidget(self.btn_fmk_build)
        fmk_layout.addLayout(ws_btns)

        # Build options
        build_opts = QHBoxLayout()
        self.chk_nopad = QCheckBox("ไม่ Pad (-nopad)")
        self.chk_min = QCheckBox("Blocksize 1MB (-min)")
        self.chk_linksys_footer = QCheckBox("Linksys Footer Fix (Auto Detect)")
        build_opts.addWidget(self.chk_nopad)
        build_opts.addWidget(self.chk_min)
        build_opts.addWidget(self.chk_linksys_footer)
        fmk_layout.addLayout(build_opts)

        # IPK
        ipk_layout = QHBoxLayout()
        self.btn_install_ipk = QPushButton("Install IPK")
        self.btn_install_ipk.clicked.connect(self.do_install_ipk)
        self.btn_remove_ipk = QPushButton("Remove IPK")
        self.btn_remove_ipk.clicked.connect(self.do_remove_ipk)
        ipk_layout.addWidget(self.btn_install_ipk)
        ipk_layout.addWidget(self.btn_remove_ipk)
        fmk_layout.addLayout(ipk_layout)

        # Meta display
        self.fmk_meta_view = QTextEdit()
        self.fmk_meta_view.setReadOnly(True)
        fmk_layout.addWidget(QLabel("FMK Metadata (config.log)"))
        fmk_layout.addWidget(self.fmk_meta_view)

        self.tabs.addTab(fmk_tab, "FMK Integration")

        # Initial info
        if not self.fmk_root:
            self.append_log("ยังไม่พบ FMK root – โปรดตั้งค่า")
        else:
            self.append_log(f"พบ FMK root: {self.fmk_root}")

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
    def append_log(self, text):
        self.log_panel.append(text)
        self.log_panel.ensureCursorVisible()

    def append_meta(self, txt):
        self.fmk_meta_view.append(txt)
        self.fmk_meta_view.ensureCursorVisible()

    # ------------- Firmware selection -------------
    def choose_firmware(self):
        path, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์ Firmware")
        if path:
            self.fw_path = path
            self.fw_line.setText(path)
            self.append_log(f"เลือก firmware: {path}")

    # ------------- FMK root selection -------------
    def choose_fmk_root(self):
        d = QFileDialog.getExistingDirectory(self, "เลือกโฟลเดอร์ FMK Root")
        if d:
            self.fmk_root = d
            self.fmk_path_line.setText(d)
            self.append_log(f"ตั้ง FMK root = {d}")

    def reload_fmk_root(self):
        root = self.fmk_path_line.text().strip()
        if not root:
            QMessageBox.warning(self,"FMK","โปรดระบุ path")
            return
        if not os.path.isdir(root):
            QMessageBox.critical(self,"FMK","ไม่พบไดเรกทอรี")
            return
        if not os.path.isfile(os.path.join(root,"extract-firmware.sh")):
            QMessageBox.warning(self,"FMK","ไม่พบ extract-firmware.sh ใน path นี้")
        self.fmk_root = root
        self.append_log(f"Reload FMK root: {root}")

    # ------------- FMK Extract -------------
    def do_fmk_extract(self):
        if not self.fmk_root:
            QMessageBox.warning(self,"FMK","ยังไม่ได้ตั้ง FMK root")
            return
        if not self.fw_line.text():
            QMessageBox.warning(self,"FMK","ยังไม่ได้เลือก firmware")
            return
        ws_name = self.ws_name_edit.text().strip()
        if not ws_name:
            ws_name = "ws_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.ws_name_edit.setText(ws_name)
        workspace = os.path.join("workspaces", ws_name)
        self.append_log(f"[FMK] เริ่ม extract → workspace: {workspace}")

        def worker():
            try:
                meta = extract_firmware(self.fmk_root, self.fw_line.text(), workspace, log_callback=self.log_emitter.log_signal.emit)
                self.fmk_workspace = workspace
                self.fmk_meta = meta
                self.log_emitter.log_signal.emit("[FMK] Extract สำเร็จ")
                # show meta
                QTimer.singleShot(0, self.render_meta)
                # Auto AI
                if self.chk_auto_analyze.isChecked():
                    fs_offset = meta.get("FS_OFFSET")
                    # ประมาณ rootfs size (footer_offset - fs_offset - FOOTER_SIZE)
                    footer_off = meta.get("FOOTER_OFFSET", meta.get("FW_SIZE",0))
                    rootfs_size = footer_off - fs_offset - meta.get("FOOTER_SIZE",0) if fs_offset else 0
                    if fs_offset and rootfs_size>0:
                        self.run_ai_analysis_with_offsets(self.fw_line.text(), fs_offset, rootfs_size)
                    else:
                        self.log_emitter.log_signal.emit("[AI] ไม่สามารถคำนวณ rootfs offset/size ได้")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def render_meta(self):
        self.fmk_meta_view.clear()
        if not self.fmk_meta:
            self.fmk_meta_view.setPlainText("No meta.")
            return
        for k,v in self.fmk_meta.items():
            self.append_meta(f"{k} = {v}")

        # heuristic detect linksys
        if detect_linksys_candidate(self.fmk_meta):
            self.append_meta("Linksys footer detected candidate → คุณสามารถใช้ Linksys Footer Fix หลัง build")
            self.chk_linksys_footer.setChecked(True)

    # ------------- FMK Build -------------
    def do_fmk_build(self):
        if not self.fmk_workspace:
            QMessageBox.warning(self,"FMK","ยังไม่มี workspace (ต้อง extract ก่อน)")
            return
        if not self.fmk_root:
            QMessageBox.warning(self,"FMK","ยังไม่ได้ตั้ง FMK root")
            return
        nopad = self.chk_nopad.isChecked()
        minblk = self.chk_min.isChecked()
        self.append_log(f"[FMK] Build start (nopad={nopad}, min={minblk})")

        def worker():
            try:
                out_fw = build_firmware(self.fmk_root, self.fmk_workspace, nopad=nopad, minblk=minblk,
                                        log_callback=self.log_emitter.log_signal.emit)
                if not out_fw:
                    self.log_emitter.log_signal.emit("[FMK] ไม่พบไฟล์ new-firmware.bin หลัง build")
                    return
                self.log_emitter.log_signal.emit(f"[FMK] Build สำเร็จ: {out_fw}")
                final_fw = out_fw
                if self.chk_linksys_footer.isChecked() and detect_linksys_candidate(self.fmk_meta):
                    self.log_emitter.log_signal.emit("[FMK] รัน Linksys Footer Fix ...")
                    mod = postprocess_linksys_footer(self.fmk_root, out_fw, log_callback=self.log_emitter.log_signal.emit)
                    if mod:
                        self.log_emitter.log_signal.emit(f"[FMK] Footer fixed: {mod}")
                        final_fw = mod
                # Copy ไป output/ ใส่ timestamp
                base_out_name = f"rebuilt_{os.path.basename(self.fw_line.text())}"
                target = os.path.join("output", base_out_name)
                shutil.copy2(final_fw, target)
                self.log_emitter.log_signal.emit(f"[FMK] Saved output → {target}")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR build: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # ------------- IPK -------------
    def do_install_ipk(self):
        if not self.fmk_workspace:
            QMessageBox.warning(self,"FMK","ยังไม่มี workspace")
            return
        path, _ = QFileDialog.getOpenFileName(self,"เลือกไฟล์ .ipk","","IPK Files (*.ipk);;All Files (*)")
        if not path: return
        self.append_log(f"[FMK] Install IPK: {path}")
        def worker():
            try:
                install_ipk(self.fmk_root, self.fmk_workspace, path, log_callback=self.log_emitter.log_signal.emit)
                self.log_emitter.log_signal.emit("[FMK] Install IPK สำเร็จ")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR IPK install: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def do_remove_ipk(self):
        if not self.fmk_workspace:
            QMessageBox.warning(self,"FMK","ยังไม่มี workspace")
            return
        path, _ = QFileDialog.getOpenFileName(self,"เลือกไฟล์ .ipk (เพื่อ reference ลบ)","","IPK Files (*.ipk);;All Files (*)")
        if not path: return
        self.append_log(f"[FMK] Remove IPK: {path}")
        def worker():
            try:
                remove_ipk(self.fmk_root, self.fmk_workspace, path, log_callback=self.log_emitter.log_signal.emit)
                self.log_emitter.log_signal.emit("[FMK] Remove IPK สำเร็จ")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"[FMK] ERROR IPK remove: {e}")
        threading.Thread(target=worker, daemon=True).start()

    # ------------- AI Analysis -------------
    def run_ai_analysis_manual(self):
        if not self.fw_line.text():
            QMessageBox.warning(self,"AI","ยังไม่ได้เลือก firmware")
            return
        # ใช้ offset/size แบบ dummy (หรือให้ผู้ใช้กรอก)
        # ในระบบจริงคุณควรเพิ่มอินพุต offset/size หรือ derive จาก meta ถ้า extract แล้ว
        if self.fmk_meta.get("FS_OFFSET") and self.fmk_meta.get("FOOTER_OFFSET"):
            fs_offset = self.fmk_meta["FS_OFFSET"]
            rootfs_size = self.fmk_meta.get("FOOTER_OFFSET", self.fmk_meta.get("FW_SIZE",0)) - fs_offset - self.fmk_meta.get("FOOTER_SIZE",0)
            self.run_ai_analysis_with_offsets(self.fw_line.text(), fs_offset, rootfs_size)
        else:
            QMessageBox.information(self,"AI","ยังไม่มี meta จาก FMK (ถ้าอยากให้ใช้ offset/size ที่ถูกต้อง ให้ Extract ก่อน) จะใช้ค่าประมาณ offset=0,size=0 - ปฏิเสธ")
            return

    def run_ai_analysis_with_offsets(self, fw_path, offset, size):
        if self.ai_running:
            self.append_log("[AI] กำลังวิเคราะห์อยู่")
            return
        self.ai_running=True
        self.btn_run_ai.setEnabled(False)
        self.append_log(f"[AI] เริ่มวิเคราะห์ offset=0x{offset:X}, size={size}")

        self.ai_thread = QThread()
        self.ai_worker = AIWorker(fw_path, offset, size)
        self.ai_worker.moveToThread(self.ai_thread)
        self.ai_thread.started.connect(self.ai_worker.run)
        self.ai_worker.log.connect(self.append_log)
        self.ai_worker.finished.connect(self.ai_done)
        self.ai_worker.error.connect(self.ai_error)
        self.ai_worker.finished.connect(self.ai_thread.quit)
        self.ai_worker.error.connect(self.ai_thread.quit)
        self.ai_thread.finished.connect(self.ai_thread.deleteLater)
        self.ai_thread.start()

    def ai_done(self, findings):
        self.analysis_result = findings
        self.append_log("[AI] วิเคราะห์เสร็จ")
        self.info_panel.clear()
        for line in findings:
            self.info_panel.append(line)
        self.ai_running=False
        self.btn_run_ai.setEnabled(True)

    def ai_error(self, msg):
        self.append_log("[AI] ERROR\n"+msg)
        self.ai_running=False
        self.btn_run_ai.setEnabled(True)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())