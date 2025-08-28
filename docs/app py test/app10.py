import sys, os, subprocess, threading, hashlib, struct, shutil, tempfile
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QFileDialog, QLabel, QComboBox, QHBoxLayout, QMessageBox, QTabWidget, QLineEdit
)
from PySide6.QtCore import Qt, Signal, QObject

PARTITION_OFFSETS = [
    (0x0000000, "Bootloader"),
    (0x0240000, "rootfs0"),
    (0x0610000, "rootfs1"),
    (0x0BC0000, "rootfs2"),
    (0x1000000, "END"),
]

def sha256sum(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024*1024)
            if not b: break
            h.update(b)
    return h.hexdigest()

def md5sum(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024*1024)
            if not b: break
            h.update(b)
    return h.hexdigest()

def get_partition_details(fw_path):
    with open(fw_path, "rb") as f:
        size = f.seek(0, 2)
        parts = []
        for i in range(len(PARTITION_OFFSETS)-1):
            start, name = PARTITION_OFFSETS[i]
            next_start, _ = PARTITION_OFFSETS[i+1]
            length = next_start - start
            f.seek(start)
            magic = f.read(4)
            parts.append({
                "name": name, "offset": f"0x{start:07X}", "size": length,
                "size_hex": f"0x{length:X}", "magic": magic.hex(), "magic_str": magic.decode(errors='replace')
            })
        return parts, size

def get_filetype(fw_path):
    try:
        out = subprocess.check_output(["file", fw_path], text=True)
        return out.strip()
    except Exception as e:
        return f"file error: {e}"

def get_entropy(fw_path, sample_size=4096, samples=16):
    import math
    res = []
    with open(fw_path, "rb") as f:
        for _ in range(samples):
            b = f.read(sample_size)
            if not b: break
            freq = [0]*256
            for x in b: freq[x] += 1
            e = -sum((c/len(b))*math.log2(c/len(b)) for c in freq if c)
            res.append(round(e, 3))
    if not res: return "-"
    return f"min={min(res):.3f}, max={max(res):.3f}, avg={sum(res)/len(res):.3f}"

class LogEmitter(QObject):
    log_signal = Signal(str)

def scan_rootfs_offset_size(fw_path, log_func=print):
    FS_SIGNATURES = [
        (b'hsqs', "squashfs"),   # squashfs little endian
        (b'sqsh', "squashfs"),   # squashfs big endian
        (b'CrAm', "cramfs"),
        (b'UBI#', "ubi"),
        (b'UBI!', "ubi"),
        (b'F2FS', "f2fs"),
        (b'JFFS', "jffs"),
    ]
    results = []
    found = None
    with open(fw_path, "rb") as f:
        data = f.read()
        for sig, name in FS_SIGNATURES:
            idx = data.find(sig)
            if idx != -1:
                results.append((name, sig, idx))
    if results:
        fs_name, sig, offset = results[0]
        next_offset = len(data)
        for _, _, idx in results[1:]:
            if idx > offset:
                next_offset = min(next_offset, idx)
        size = next_offset - offset
        log_func(f"พบไฟล์ระบบ: {fs_name} (offset=0x{offset:X} size=0x{size:X})")
        return {"fs": fs_name, "offset": offset, "size": size, "all": results}
    else:
        log_func("ไม่พบ signature ของ rootfs อัตโนมัติ")
        return None

def analyze_firmware_auto(fw_path, rootfs_offset, rootfs_size, log_func=print):
    result = []
    # 1. วิเคราะห์ boot delay (offset 0x100)
    try:
        with open(fw_path, "rb") as f:
            f.seek(0x100)
            bootdelay_byte = f.read(1)
            if bootdelay_byte:
                bootdelay = bootdelay_byte[0]
                if bootdelay == 0:
                    result.append("Boot delay = 0 วินาที (ไม่มี delay) — ปกติถ้าเน้น boot เร็ว แต่ debug อาจไม่ทัน")
                elif bootdelay > 9:
                    result.append(f"Boot delay พบค่า {bootdelay} > 9 วินาที (อาจผิดปกติ)")
                elif bootdelay > 3:
                    result.append(f"Boot delay พบค่า {bootdelay} วินาที — ค่อนข้างนาน อาจต้องการลดลง")
                else:
                    result.append(f"Boot delay = {bootdelay} วินาที (ปกติ)")
            else:
                result.append("ไม่สามารถอ่านค่า boot delay ณ offset 0x100 ได้")
    except Exception as e:
        result.append(f"อ่าน boot delay ผิดพลาด: {e}")

    # 2. วิเคราะห์ rootfs ที่ offset/size ที่กำหนด
    tmpdir = tempfile.mkdtemp(prefix="fw-rootfs-")
    try:
        rootfs_bin = os.path.join(tmpdir, "rootfs0.bin")
        with open(fw_path, "rb") as f:
            f.seek(rootfs_offset)
            rootfs = f.read(rootfs_size)
            with open(rootfs_bin, "wb") as fo:
                fo.write(rootfs)
        unsquashfs_dir = os.path.join(tmpdir, "unsquashfs")
        os.makedirs(unsquashfs_dir)
        try:
            subprocess.check_output(
                ["unsquashfs", "-d", unsquashfs_dir, rootfs_bin],
                stderr=subprocess.STDOUT, timeout=30
            )
            inittab_path = os.path.join(unsquashfs_dir, "etc", "inittab")
            has_serial_shell = False
            if os.path.exists(inittab_path):
                with open(inittab_path, "r", encoding="utf-8", errors="ignore") as f_inittab:
                    for line in f_inittab:
                        if "getty" in line and ("/dev/ttyS" in line or "ttyS" in line):
                            has_serial_shell = True
                            break
                if has_serial_shell:
                    result.append("พบ getty (shell) บน serial port ใน inittab — ไม่ต้อง patch shell debug serial")
                else:
                    result.append("ไม่พบ getty (shell) บน serial port — แนะนำ patch shell debug serial")
            else:
                result.append("หาไฟล์ /etc/inittab ไม่เจอ — อาจไม่มี shell serial")

            inetd_path = os.path.join(unsquashfs_dir, "etc", "inetd.conf")
            has_telnet = has_ftp = False
            if os.path.exists(inetd_path):
                with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f_inetd:
                    txt = f_inetd.read()
                    if "telnet" in txt:
                        has_telnet = True
                    if "ftp" in txt:
                        has_ftp = True
            if has_telnet:
                result.append("พบบริการ Telnet ใน inetd.conf — ไม่ต้อง patch telnet")
            else:
                result.append("ไม่พบ Telnet service — แนะนำ patch telnet เพิ่ม")
            if has_ftp:
                result.append("พบบริการ FTP ใน inetd.conf — ไม่ต้อง patch ftp")
            else:
                result.append("ไม่พบ FTP service — แนะนำ patch ftp เพิ่ม")

            passwd_path = os.path.join(unsquashfs_dir, "etc", "passwd")
            shadow_path = os.path.join(unsquashfs_dir, "etc", "shadow")
            if os.path.exists(passwd_path):
                with open(passwd_path, "r", encoding="utf-8", errors="ignore") as f_passwd:
                    users = [line.split(":")[0] for line in f_passwd if ":" in line]
                    result.append(f"User ที่พบในระบบ: {', '.join(users)}")
            if os.path.exists(shadow_path):
                with open(shadow_path, "r", encoding="utf-8", errors="ignore") as f_shadow:
                    for line in f_shadow:
                        if ":" in line:
                            user, passwd = line.split(":", 1)
                            if passwd.strip() in ("", "!", "*"):
                                result.append(f"User {user} ไม่มีรหัสผ่านหรือถูกล็อก")
                            elif passwd.strip() == "x":
                                result.append(f"User {user} ใช้ shadow password (ปลอดภัย)")
                            else:
                                result.append(f"User {user} มี hash password: {passwd.strip()[:10]}...")
        except Exception as e:
            result.append(f"unsquashfs/วิเคราะห์ rootfs ผิดพลาด: {e}")

    finally:
        shutil.rmtree(tmpdir)

    ai_patch_plan = {
        "patch_bootdelay": False,
        "patch_shell_serial": False,
        "patch_telnet": False,
        "patch_ftp": False,
        "bootdelay_value": 1
    }
    for line in result:
        if "boot delay" in line.lower() and "แนะนำ" in line.lower():
            ai_patch_plan["patch_bootdelay"] = True
        if "boot delay = 0" in line.lower():
            ai_patch_plan["patch_bootdelay"] = True
            ai_patch_plan["bootdelay_value"] = 1
        elif "boot delay พบค่า" in line.lower():
            try:
                import re
                m = re.search(r'พบค่า\s*([0-9]+)', line)
                if m:
                    v = int(m.group(1))
                    ai_patch_plan["bootdelay_value"] = v
            except:
                pass
    for line in result:
        if "แนะนำ patch shell debug serial" in line:
            ai_patch_plan["patch_shell_serial"] = True
        if "แนะนำ patch telnet" in line:
            ai_patch_plan["patch_telnet"] = True
        if "แนะนำ patch ftp" in line:
            ai_patch_plan["patch_ftp"] = True
    return result, ai_patch_plan

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(1150, 820)
        self.fw_path = None
        self.patched_fw = None
        self.rootfs_offset = None
        self.rootfs_size = None

        self.input_dir = os.path.abspath("input")
        self.output_dir = os.path.abspath("output")
        os.makedirs(self.input_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

        self.toolkit_path = os.path.abspath("firmware_toolkit.sh")
        if os.path.exists(self.toolkit_path):
            os.chmod(self.toolkit_path, 0o755)

        self.log_emitter = LogEmitter()
        self.log_emitter.log_signal.connect(self.log)

        central = QWidget()
        main_layout = QVBoxLayout(central)

        inout_layout = QHBoxLayout()
        inout_layout.addWidget(QLabel("Input folder:"))
        self.input_edit = QLineEdit(self.input_dir)
        inout_layout.addWidget(self.input_edit)
        self.btn_select_input = QPushButton("เลือกโฟลเดอร์ Input")
        self.btn_select_input.clicked.connect(self.select_input_folder)
        inout_layout.addWidget(self.btn_select_input)
        inout_layout.addWidget(QLabel("Output folder:"))
        self.output_edit = QLineEdit(self.output_dir)
        inout_layout.addWidget(self.output_edit)
        self.btn_select_output = QPushButton("เลือกโฟลเดอร์ Output")
        self.btn_select_output.clicked.connect(self.select_output_folder)
        inout_layout.addWidget(self.btn_select_output)
        main_layout.addLayout(inout_layout)

        scanfs_layout = QHBoxLayout()
        scanfs_layout.addWidget(QLabel("RootFS Offset (hex):"))
        self.rootfs_offset_edit = QLineEdit("0x0240000")
        scanfs_layout.addWidget(self.rootfs_offset_edit)
        scanfs_layout.addWidget(QLabel("RootFS Size (hex):"))
        self.rootfs_size_edit = QLineEdit("0x03D0000")
        scanfs_layout.addWidget(self.rootfs_size_edit)
        self.btn_auto_detect_rootfs = QPushButton("Auto Detect RootFS Offset/Size")
        self.btn_auto_detect_rootfs.clicked.connect(self.auto_detect_rootfs)
        scanfs_layout.addWidget(self.btn_auto_detect_rootfs)
        main_layout.addLayout(scanfs_layout)

        self.tabs = QTabWidget()
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.info_view = QTextEdit()
        self.info_view.setReadOnly(True)
        self.tabs.addTab(self.log_view, "Log")
        self.tabs.addTab(self.info_view, "Info")

        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("ตั้ง Boot Delay (วินาที):"))
        self.delay_combo = QComboBox()
        self.delay_combo.addItems([str(i) for i in range(10)])
        delay_layout.addWidget(self.delay_combo)
        self.btn_patch_delay = QPushButton("Patch Boot Delay")
        self.btn_patch_delay.clicked.connect(self.patch_boot_delay)
        delay_layout.addWidget(self.btn_patch_delay)
        main_layout.addLayout(delay_layout)

        shell_layout = QHBoxLayout()
        self.btn_patch_serial = QPushButton("Patch Shell Debug Serial")
        self.btn_patch_serial.clicked.connect(self.patch_shell_serial)
        shell_layout.addWidget(self.btn_patch_serial)
        self.btn_patch_network = QPushButton("Patch Shell Network (Telnet/FTP)")
        self.btn_patch_network.clicked.connect(self.patch_shell_network)
        shell_layout.addWidget(self.btn_patch_network)
        main_layout.addLayout(shell_layout)

        self.btn_patch_all = QPushButton("ทำ Patch รวมทุกอย่าง (Boot Delay + Shell Serial + Network)")
        self.btn_patch_all.clicked.connect(self.patch_all)
        main_layout.addWidget(self.btn_patch_all)

        self.btn_ai_auto = QPushButton("AI วิเคราะห์และแก้ไข Firmware อัตโนมัติ (วิเคราะห์+Patch)")
        self.btn_ai_auto.clicked.connect(self.ai_auto_patch)
        main_layout.addWidget(self.btn_ai_auto)

        self.btn_verify = QPushButton("ตรวจสอบความถูกต้องของ Firmware หลัง Patch")
        self.btn_verify.clicked.connect(self.verify_firmware)
        main_layout.addWidget(self.btn_verify)

        self.btn_fw_info = QPushButton("ตรวจสอบ / วิเคราะห์รายละเอียด Firmware")
        self.btn_fw_info.clicked.connect(self.show_fw_info)
        main_layout.addWidget(self.btn_fw_info)

        main_layout.addWidget(self.tabs)

        self.btn_select_fw = QPushButton("เลือกไฟล์ Firmware")
        self.btn_select_fw.clicked.connect(self.select_firmware)
        main_layout.addWidget(self.btn_select_fw)

        self.setCentralWidget(central)

    def log(self, text):
        self.log_view.append(text)
        self.log_view.ensureCursorVisible()

    def info(self, text):
        self.info_view.append(text)
        self.info_view.ensureCursorVisible()

    def select_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "เลือกโฟลเดอร์ Input", self.input_dir)
        if folder:
            self.input_dir = folder
            self.input_edit.setText(folder)
            os.makedirs(self.input_dir, exist_ok=True)

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "เลือกโฟลเดอร์ Output", self.output_dir)
        if folder:
            self.output_dir = folder
            self.output_edit.setText(folder)
            os.makedirs(self.output_dir, exist_ok=True)

    def select_firmware(self):
        file, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์เฟิร์มแวร์")
        if file:
            base = os.path.basename(file)
            dest = os.path.join(self.input_dir, f"original_{base}")
            if not os.path.exists(dest):
                shutil.copy2(file, dest)
                self.log(f"สำเนา firmware ดั้งเดิมไว้ที่: {dest}")
            else:
                self.log(f"พบ original firmware ที่: {dest}")
            self.fw_path = dest
            self.patched_fw = None
            self.log(f"เลือกไฟล์: {self.fw_path}")

    def auto_detect_rootfs(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        result = scan_rootfs_offset_size(self.fw_path, log_func=self.info)
        if result:
            self.rootfs_offset = result["offset"]
            self.rootfs_size = result["size"]
            self.rootfs_offset_edit.setText(f"0x{self.rootfs_offset:X}")
            self.rootfs_size_edit.setText(f"0x{self.rootfs_size:X}")
            self.info(f"RootFS Offset/Size ถูกตั้งอัตโนมัติ: 0x{self.rootfs_offset:X} / 0x{self.rootfs_size:X}")
        else:
            self.rootfs_offset = None
            self.rootfs_size = None
            self.info("ไม่พบ rootfs อัตโนมัติ กรุณากรอกเอง")

    def get_rootfs_offset_size(self):
        try:
            offset = int(self.rootfs_offset_edit.text(), 16)
            size = int(self.rootfs_size_edit.text(), 16)
            return offset, size
        except Exception as e:
            QMessageBox.warning(self, "RootFS Offset/Size ไม่ถูกต้อง", "กรุณากรอกค่า RootFS Offset/Size ให้ถูกต้อง (เช่น 0x0240000 / 0x03D0000)")
            return None, None

    def _run_toolkit(self, args, patched_out=None, callback=None):
        if os.path.exists(self.toolkit_path):
            os.chmod(self.toolkit_path, 0o755)
        def worker():
            self.log_emitter.log_signal.emit(f"เรียก {' '.join(args)}")
            try:
                proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
                )
                for line in iter(proc.stdout.readline, ""):
                    self.log_emitter.log_signal.emit(line.strip())
                proc.stdout.close()
                proc.wait()
                if proc.returncode == 0:
                    self.log_emitter.log_signal.emit("✅ เสร็จสมบูรณ์")
                    if patched_out:
                        self.patched_fw = patched_out
                    if callback:
                        callback()
                else:
                    self.log_emitter.log_signal.emit("❌ พบข้อผิดพลาด")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"❌ {e}")
        threading.Thread(target=worker, daemon=True).start()

    def patch_boot_delay(self, delay_override=None, input_fw=None, out_file=None, callback=None):
        if not input_fw and not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        delay = str(delay_override) if delay_override is not None else self.delay_combo.currentText()
        base = os.path.basename(input_fw or self.fw_path)
        out_file = out_file or os.path.join(self.output_dir, f"patched_delay_{delay}_{base}")
        args = [self.toolkit_path, "patch", "--input", input_fw or self.fw_path, "--output", out_file, "--bootdelay", delay]
        self._run_toolkit(args, patched_out=out_file, callback=callback)
        return out_file

    def patch_shell_serial(self, input_fw=None, out_file=None, callback=None):
        if not input_fw and not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        base = os.path.basename(input_fw or self.fw_path)
        out_file = out_file or os.path.join(self.output_dir, f"patched_serial_{base}")
        args = [
            self.toolkit_path, "patch-rootfs0-services",
            "--input", input_fw or self.fw_path, "--output", out_file,
            "--ports", "ttyS1", "--remove-others"
        ]
        self._run_toolkit(args, patched_out=out_file, callback=callback)
        return out_file

    def patch_shell_network(self, input_fw=None, out_file=None, callback=None):
        if not input_fw and not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        base = os.path.basename(input_fw or self.fw_path)
        out_file = out_file or os.path.join(self.output_dir, f"patched_network_{base}")
        args = [
            self.toolkit_path, "patch-rootfs0-services",
            "--input", input_fw or self.fw_path, "--output", out_file,
            "--ports", "ttyS1", "--remove-others",
            "--enable-telnet", "--telnet-port", "23",
            "--enable-ftp", "--ftp-port", "21", "--ftp-root", "/"
        ]
        self._run_toolkit(args, patched_out=out_file, callback=callback)
        return out_file

    def patch_all(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        delay = self.delay_combo.currentText()
        base = os.path.basename(self.fw_path)
        delay_out = os.path.join(self.output_dir, f"patched_delay_{delay}_{base}")
        def after_delay():
            serial_out = os.path.join(self.output_dir, f"patched_serial_{delay}_{base}")
            def after_serial():
                net_out = os.path.join(self.output_dir, f"patched_all_{delay}_{base}")
                self.patch_shell_network(input_fw=serial_out, out_file=net_out)
            self.patch_shell_serial(input_fw=delay_out, out_file=serial_out, callback=after_serial)
        self.patch_boot_delay(delay_override=delay, input_fw=self.fw_path, out_file=delay_out, callback=after_delay)

    def ai_auto_patch(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        offset, size = self.get_rootfs_offset_size()
        if offset is None or size is None:
            return
        self.info_view.clear()
        self.info("=== วิเคราะห์ Firmware อัตโนมัติ ===")
        def ai_worker():
            findings, ai_patch_plan = analyze_firmware_auto(self.fw_path, offset, size, log_func=self.info)
            for line in findings:
                self.info(line)
            patch_steps = []
            fw_base = os.path.basename(self.fw_path)
            fw_in = self.fw_path
            fw_prev = fw_in
            if ai_patch_plan["patch_bootdelay"]:
                self.info(f"AI: เตรียม Patch Boot Delay ({ai_patch_plan['bootdelay_value']} วินาที)")
                fw_out = os.path.join(self.output_dir, f"ai_patched_delay_{fw_base}")
                patch_steps.append(('bootdelay', fw_prev, fw_out, ai_patch_plan['bootdelay_value']))
                fw_prev = fw_out
            if ai_patch_plan["patch_shell_serial"]:
                self.info("AI: เตรียม Patch Shell Debug Serial")
                fw_out = os.path.join(self.output_dir, f"ai_patched_serial_{fw_base}")
                patch_steps.append(('serial', fw_prev, fw_out, None))
                fw_prev = fw_out
            if ai_patch_plan["patch_telnet"] or ai_patch_plan["patch_ftp"]:
                self.info("AI: เตรียม Patch Network (Telnet/FTP)")
                fw_out = os.path.join(self.output_dir, f"ai_patched_network_{fw_base}")
                patch_steps.append(('network', fw_prev, fw_out, None))
                fw_prev = fw_out
            if not patch_steps:
                self.info("AI: ไม่พบจุดที่ต้อง patch เพิ่มเติม")
                return
            def run_steps(idx):
                if idx >= len(patch_steps):
                    self.info("AI: Auto Patch เสร็จสมบูรณ์")
                    self.patched_fw = patch_steps[-1][2]
                    return
                kind, in_fw, out_fw, val = patch_steps[idx]
                if kind == 'bootdelay':
                    self.patch_boot_delay(delay_override=val, input_fw=in_fw, out_file=out_fw, callback=lambda: run_steps(idx+1))
                elif kind == 'serial':
                    self.patch_shell_serial(input_fw=in_fw, out_file=out_fw, callback=lambda: run_steps(idx+1))
                elif kind == 'network':
                    self.patch_shell_network(input_fw=in_fw, out_file=out_fw, callback=lambda: run_steps(idx+1))
            run_steps(0)
        threading.Thread(target=ai_worker, daemon=True).start()

    def verify_firmware(self):
        fw = self.patched_fw or self.fw_path
        if not fw:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        args = [self.toolkit_path, "verify-rootfs", "--input", fw, "--index", "0", "--port", "ttyS1"]
        self._run_toolkit(args, patched_out=None)

    def show_fw_info(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        self.info_view.clear()
        self.info(f"*** ข้อมูลไฟล์ Firmware ***\n{self.fw_path}\n")
        try:
            s = os.stat(self.fw_path)
            self.info(f"ขนาดไฟล์: {s.st_size} bytes\nSHA256: {sha256sum(self.fw_path)}\nMD5: {md5sum(self.fw_path)}\n")
        except Exception as e:
            self.info(f"stat error: {e}\n")
        try:
            self.info(f"ชนิดไฟล์: {get_filetype(self.fw_path)}\n")
        except Exception as e:
            self.info(f"filetype error: {e}\n")
        try:
            self.info(f"Entropy (ตัวอย่าง): {get_entropy(self.fw_path)}\n")
        except Exception as e:
            self.info(f"entropy error: {e}\n")
        try:
            parts, size = get_partition_details(self.fw_path)
            self.info("Partition Table:")
            for p in parts:
                self.info(f"  {p['name']:10}  Offset={p['offset']}  Size={p['size_hex']}  Magic={p['magic']} ({p['magic_str']})")
        except Exception as e:
            self.info(f"partition error: {e}\n")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())