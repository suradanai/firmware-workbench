import sys, os, subprocess, threading, hashlib, struct, shutil, tempfile, random, string
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QFileDialog, QLabel, QComboBox, QHBoxLayout, QMessageBox, QTabWidget, QLineEdit
)
from PySide6.QtCore import Qt, Signal, QObject

from passlib.hash import sha512_crypt

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
    PARTITION_OFFSETS = [
        (0x0000000, "Bootloader"),
        (0x0240000, "rootfs0"),
        (0x0610000, "rootfs1"),
        (0x0BC0000, "rootfs2"),
        (0x1000000, "END"),
    ]
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

def analyze_firmware_detailed(fw_path, rootfs_offset, rootfs_size, log_func):
    findings = []
    try:
        log_func(">> วิเคราะห์ boot delay ...")
        with open(fw_path, "rb") as f:
            f.seek(0x100)
            bootdelay_byte = f.read(1)
            if bootdelay_byte:
                bootdelay = bootdelay_byte[0]
                log_func(f"boot delay byte: {bootdelay}")
                if bootdelay == 0:
                    findings.append("Boot delay = 0 วินาที (ไม่มี delay) — ปกติถ้าเน้น boot เร็ว แต่ debug อาจไม่ทัน")
                elif bootdelay > 9:
                    findings.append(f"Boot delay พบค่า {bootdelay} > 9 วินาที (อาจผิดปกติ)")
                elif bootdelay > 3:
                    findings.append(f"Boot delay พบค่า {bootdelay} วินาที — ค่อนข้างนาน อาจต้องการลดลง")
                else:
                    findings.append(f"Boot delay = {bootdelay} วินาที (ปกติ)")
            else:
                findings.append("ไม่สามารถอ่านค่า boot delay ณ offset 0x100 ได้")
    except Exception as e:
        findings.append(f"อ่าน boot delay ผิดพลาด: {e}")

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
        log_func(">> แตกไฟล์ rootfs ...")
        try:
            subprocess.check_output(
                ["unsquashfs", "-d", unsquashfs_dir, rootfs_bin],
                stderr=subprocess.STDOUT, timeout=30
            )
            log_func(">> แตก rootfs สำเร็จ")
            # inittab
            inittab_path = os.path.join(unsquashfs_dir, "etc", "inittab")
            has_serial_shell = False
            if os.path.exists(inittab_path):
                with open(inittab_path, "r", encoding="utf-8", errors="ignore") as f_inittab:
                    for line in f_inittab:
                        if "getty" in line and ("/dev/ttyS" in line or "ttyS" in line):
                            has_serial_shell = True
                            break
                if has_serial_shell:
                    findings.append("พบ getty (shell) บน serial port ใน inittab — ปลอดภัยสำหรับ debug")
                else:
                    findings.append("ไม่พบ getty (shell) บน serial port — ไม่มี shell debug serial")
            else:
                findings.append("หาไฟล์ /etc/inittab ไม่เจอ — อาจไม่มี shell serial")
            # inetd
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
                findings.append("พบบริการ Telnet ใน inetd.conf — มี telnet")
            else:
                findings.append("ไม่พบ Telnet service")
            if has_ftp:
                findings.append("พบบริการ FTP ใน inetd.conf — มี ftp")
            else:
                findings.append("ไม่พบ FTP service")
            # user/password
            passwd_path = os.path.join(unsquashfs_dir, "etc", "passwd")
            shadow_path = os.path.join(unsquashfs_dir, "etc", "shadow")
            if os.path.exists(passwd_path):
                with open(passwd_path, "r", encoding="utf-8", errors="ignore") as f_passwd:
                    users = [line.split(":")[0] for line in f_passwd if ":" in line]
                    findings.append(f"User ที่พบในระบบ: {', '.join(users)}")
            if os.path.exists(shadow_path):
                with open(shadow_path, "r", encoding="utf-8", errors="ignore") as f_shadow:
                    for line in f_shadow:
                        if ":" in line:
                            user, passwd = line.split(":", 1)
                            if passwd.strip() in ("", "!", "*"):
                                findings.append(f"User {user} ไม่มีรหัสผ่านหรือถูกล็อก")
                            elif passwd.strip() == "x":
                                findings.append(f"User {user} ใช้ shadow password (ปลอดภัย)")
                            else:
                                findings.append(f"User {user} มี hash password: {passwd.strip()[:10]}...")
            # ตรวจสอบไฟล์สำคัญ
            log_func(">> ตรวจสอบ busybox, init, rcS ...")
            for fname in ["bin/busybox", "sbin/init", "etc/init.d/rcS"]:
                fpath = os.path.join(unsquashfs_dir, fname)
                if os.path.exists(fpath):
                    findings.append(f"พบ {fname}")
                else:
                    findings.append(f"ไม่พบ {fname}")
            # ตรวจสอบขนาดและ entropy rootfs
            rfs_stat = os.stat(rootfs_bin)
            findings.append(f"ขนาด rootfs: {rfs_stat.st_size} bytes")
            findings.append(f"entropy rootfs: {get_entropy(rootfs_bin)}")
        except Exception as e:
            findings.append(f"unsquashfs/วิเคราะห์ rootfs ผิดพลาด: {e}")

    finally:
        shutil.rmtree(tmpdir)

    # ตรวจสอบ partition, magic, entropy firmware
    try:
        log_func(">> ตรวจสอบ partition และ magic number ...")
        parts, _ = get_partition_details(fw_path)
        for p in parts:
            findings.append(f"Partition {p['name']} Offset={p['offset']} Size={p['size_hex']} Magic={p['magic']} ({p['magic_str']})")
    except Exception as e:
        findings.append(f"partition error: {e}")

    try:
        log_func(">> ตรวจสอบ entropy firmware ...")
        findings.append(f"entropy firmware: {get_entropy(fw_path)}")
    except Exception as e:
        findings.append(f"entropy error: {e}")

    return findings

def get_supported_squashfs_compressions():
    try:
        out = subprocess.check_output(["mksquashfs", "-help"], text=True, stderr=subprocess.STDOUT)
        if "xz" in out:
            return ["xz", "gzip"]
        else:
            return ["gzip"]
    except Exception:
        return ["gzip"]

def mksquashfs_cmd(folder, outfile, timeout=60):
    comps = get_supported_squashfs_compressions()
    for comp in comps:
        try:
            subprocess.check_output(
                ["mksquashfs", folder, outfile, "-noappend", "-comp", comp],
                stderr=subprocess.STDOUT,
                timeout=timeout
            )
            return True
        except Exception as e:
            continue
    return False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(1300, 900)
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

        # ปุ่ม AI วิเคราะห์ Firmware (ไม่แก้ไขแล้ว)
        self.btn_ai_analyze = QPushButton("AI วิเคราะห์ Firmware โดยละเอียด (เฉพาะวิเคราะห์)")
        self.btn_ai_analyze.clicked.connect(self.ai_analyze_only)
        main_layout.addWidget(self.btn_ai_analyze)

        patch_root_layout = QHBoxLayout()
        patch_root_layout.addWidget(QLabel("รหัสผ่าน root ใหม่ (เว้นว่าง=ไม่มีรหัส):"))
        self.rootpw_edit = QLineEdit()
        self.rootpw_edit.setEchoMode(QLineEdit.Password)
        patch_root_layout.addWidget(self.rootpw_edit)
        self.btn_patch_rootpw = QPushButton("Patch รหัส Root ใน Shadow (sha512+salt)")
        self.btn_patch_rootpw.clicked.connect(self.patch_root_password)
        patch_root_layout.addWidget(self.btn_patch_rootpw)
        main_layout.addLayout(patch_root_layout)

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
        # robust: ensure delay is always a number as string
        if delay_override is not None:
            try:
                delay = str(int(delay_override))
            except Exception:
                delay = "1"
        else:
            delay = self.delay_combo.currentText()
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

    def ai_analyze_only(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        offset, size = self.get_rootfs_offset_size()
        if offset is None or size is None:
            return
        self.info_view.clear()
        self.log("=== เริ่ม AI วิเคราะห์ Firmware โดยละเอียด (ไม่แก้ไข) ===")
        def ai_worker():
            try:
                self.log("กำลังวิเคราะห์ firmware ...")
                findings = analyze_firmware_detailed(self.fw_path, offset, size, log_func=self.log_emitter.log_signal.emit)
                self.log("==== สรุปผลวิเคราะห์ ====")
                for line in findings:
                    self.log(line)
                self.log("==== จบการวิเคราะห์ AI ====")
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.log(f"❌ วิเคราะห์ผิดพลาด: {e}\n{tb}")
        threading.Thread(target=ai_worker, daemon=True).start()

    def patch_root_password(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        offset, size = self.get_rootfs_offset_size()
        if offset is None or size is None:
            return

        password = self.rootpw_edit.text()
        base = os.path.basename(self.fw_path)
        out_file = os.path.join(self.output_dir, f"patched_rootpw_{base}")

        tmpdir = tempfile.mkdtemp(prefix="rootpw-")
        rootfs_bin = os.path.join(tmpdir, "rootfs0.bin")
        with open(self.fw_path, "rb") as f:
            f.seek(offset)
            rootfs = f.read(size)
            with open(rootfs_bin, "wb") as fo:
                fo.write(rootfs)
        unsquashfs_dir = os.path.join(tmpdir, "unsquashfs")
        os.makedirs(unsquashfs_dir)
        try:
            subprocess.check_output(
                ["unsquashfs", "-d", unsquashfs_dir, rootfs_bin],
                stderr=subprocess.STDOUT, timeout=30
            )
        except Exception as e:
            shutil.rmtree(tmpdir)
            self.log(f"❌ แตก rootfs ไม่สำเร็จ: {e}")
            QMessageBox.critical(self, "ผิดพลาด", f"แตก rootfs ไม่สำเร็จ: {e}")
            return

        shadow_path = os.path.join(unsquashfs_dir, "etc", "shadow")
        if not os.path.exists(shadow_path):
            shutil.rmtree(tmpdir)
            self.log("❌ ไม่พบไฟล์ /etc/shadow ใน rootfs")
            QMessageBox.critical(self, "ผิดพลาด", "ไม่พบไฟล์ /etc/shadow ใน rootfs")
            return

        if password == "":
            new_hash = "!"
        else:
            new_hash = sha512_crypt.hash(password, rounds=5000)

        with open(shadow_path, "r") as f:
            lines = f.readlines()
        new_lines = []
        found = False
        for line in lines:
            if line.startswith("root:"):
                found = True
                parts = line.split(":")
                parts[1] = new_hash
                new_lines.append(":".join(parts))
            else:
                new_lines.append(line)
        if not found:
            shutil.rmtree(tmpdir)
            self.log("❌ ไม่พบ user root ใน /etc/shadow")
            QMessageBox.critical(self, "ผิดพลาด", "ไม่พบ user root ใน /etc/shadow")
            return
        with open(shadow_path, "w") as f:
            for l in new_lines:
                f.write(l if l.endswith("\n") else l + "\n")

        new_rootfs_bin = os.path.join(tmpdir, "new_rootfs0.bin")
        if not mksquashfs_cmd(unsquashfs_dir, new_rootfs_bin, timeout=90):
            shutil.rmtree(tmpdir)
            self.log("❌ สร้าง squashfs ไม่สำเร็จ (ลองทั้ง xz/gzip แล้ว)")
            QMessageBox.critical(self, "ผิดพลาด", "สร้าง squashfs ไม่สำเร็จ (ลองทั้ง xz/gzip แล้ว)")
            return

        with open(self.fw_path, "rb") as f:
            fw_data = bytearray(f.read())
        with open(new_rootfs_bin, "rb") as f:
            new_rootfs_data = f.read()
        fw_data[offset:offset+len(new_rootfs_data)] = new_rootfs_data
        if len(new_rootfs_data) < size:
            fw_data[offset+len(new_rootfs_data):offset+size] = b"\x00" * (size - len(new_rootfs_data))
        with open(out_file, "wb") as f:
            f.write(fw_data)

        shutil.rmtree(tmpdir)
        self.log(f"✅ Patch root password สำเร็จ: {out_file}")
        QMessageBox.information(self, "สำเร็จ", f"Patch root password ใน shadow สำเร็จ!\nไฟล์: {out_file}")
        self.patched_fw = out_file

    def verify_firmware(self):
        fw = self.patched_fw or self.fw_path
        if not fw:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return

        def verify_worker():
            self.log("=== เริ่มตรวจสอบความถูกต้องของ Firmware (หลัง patch) ===")
            try:
                self.log(f"ไฟล์: {fw}")
                s = os.stat(fw)
                self.log(f"ขนาดไฟล์: {s.st_size} bytes")
                self.log(f"SHA256: {sha256sum(fw)}")
                self.log(f"MD5: {md5sum(fw)}")
                self.log(f"ชนิดไฟล์: {get_filetype(fw)}")
                self.log(f"Entropy (ตัวอย่าง): {get_entropy(fw)}")

                parts, size = get_partition_details(fw)
                self.log("Partition Table:")
                for p in parts:
                    self.log(f"  {p['name']:10}  Offset={p['offset']}  Size={p['size_hex']}  Magic={p['magic']} ({p['magic_str']})")

                offset, size = self.get_rootfs_offset_size()
                self.log(f"ตรวจสอบ rootfs (offset=0x{offset:X}, size=0x{size:X}) ...")
                tmpdir = tempfile.mkdtemp(prefix="verify-fw-")
                rootfs_bin = os.path.join(tmpdir, "rootfs0.bin")
                with open(fw, "rb") as f_in:
                    f_in.seek(offset)
                    rootfs = f_in.read(size)
                    with open(rootfs_bin, "wb") as fo:
                        fo.write(rootfs)
                unsquashfs_dir = os.path.join(tmpdir, "unsquashfs")
                os.makedirs(unsquashfs_dir)
                try:
                    subprocess.check_output(
                        ["unsquashfs", "-d", unsquashfs_dir, rootfs_bin],
                        stderr=subprocess.STDOUT, timeout=30
                    )
                    self.log("แตก rootfs (squashfs) สำเร็จ")
                    inittab_path = os.path.join(unsquashfs_dir, "etc", "inittab")
                    if os.path.exists(inittab_path):
                        with open(inittab_path, "r", encoding="utf-8", errors="ignore") as f_inittab:
                            inittab_txt = f_inittab.read()
                        self.log("[/etc/inittab]")
                        self.log(inittab_txt)
                    else:
                        self.log("ไม่พบไฟล์ /etc/inittab")
                    shadow_path = os.path.join(unsquashfs_dir, "etc", "shadow")
                    if os.path.exists(shadow_path):
                        with open(shadow_path, "r", encoding="utf-8", errors="ignore") as f_shadow:
                            shadow_txt = f_shadow.read()
                        self.log("[/etc/shadow]")
                        self.log(shadow_txt)
                    else:
                        self.log("ไม่พบไฟล์ /etc/shadow")
                    passwd_path = os.path.join(unsquashfs_dir, "etc", "passwd")
                    if os.path.exists(passwd_path):
                        with open(passwd_path, "r", encoding="utf-8", errors="ignore") as f_passwd:
                            passwd_txt = f_passwd.read()
                        self.log("[/etc/passwd]")
                        self.log(passwd_txt)
                    else:
                        self.log("ไม่พบไฟล์ /etc/passwd")
                except Exception as e:
                    self.log(f"❌ แตก rootfs ไม่สำเร็จ: {e}")
                finally:
                    shutil.rmtree(tmpdir)
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                self.log(f"❌ ตรวจสอบผิดพลาด: {e}\n{tb}")
            self.log("=== ตรวจสอบเสร็จสิ้น ===")
        threading.Thread(target=verify_worker, daemon=True).start()

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