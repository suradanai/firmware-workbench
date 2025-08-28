import sys, os, subprocess, threading, hashlib, struct, shutil
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

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(1000, 800)
        self.fw_path = None
        self.patched_fw = None

        # Input/output directories
        self.input_dir = os.path.abspath("input")
        self.output_dir = os.path.abspath("output")
        os.makedirs(self.input_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

        self.toolkit_path = os.path.abspath("firmware_toolkit.sh")
        if os.path.exists(self.toolkit_path):
            os.chmod(self.toolkit_path, 0o755)

        # Log signal emitter
        self.log_emitter = LogEmitter()
        self.log_emitter.log_signal.connect(self.log)

        # Main layout
        central = QWidget()
        main_layout = QVBoxLayout(central)

        # Input/output folder controls
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

        # Tabs
        self.tabs = QTabWidget()
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.info_view = QTextEdit()
        self.info_view.setReadOnly(True)
        self.tabs.addTab(self.log_view, "Log")
        self.tabs.addTab(self.info_view, "Info")

        # Boot Delay Control
        delay_layout = QHBoxLayout()
        delay_layout.addWidget(QLabel("ตั้ง Boot Delay (วินาที):"))
        self.delay_combo = QComboBox()
        self.delay_combo.addItems([str(i) for i in range(10)])
        delay_layout.addWidget(self.delay_combo)
        self.btn_patch_delay = QPushButton("Patch Boot Delay")
        self.btn_patch_delay.clicked.connect(self.patch_boot_delay)
        delay_layout.addWidget(self.btn_patch_delay)
        main_layout.addLayout(delay_layout)

        # Patch Shell Control
        shell_layout = QHBoxLayout()
        self.btn_patch_serial = QPushButton("Patch Shell Debug Serial")
        self.btn_patch_serial.clicked.connect(self.patch_shell_serial)
        shell_layout.addWidget(self.btn_patch_serial)
        self.btn_patch_network = QPushButton("Patch Shell Network (Telnet/FTP)")
        self.btn_patch_network.clicked.connect(self.patch_shell_network)
        shell_layout.addWidget(self.btn_patch_network)
        main_layout.addLayout(shell_layout)

        # Patch All Button
        self.btn_patch_all = QPushButton("ทำ Patch รวมทุกอย่าง (Boot Delay + Shell Serial + Network)")
        self.btn_patch_all.clicked.connect(self.patch_all)
        main_layout.addWidget(self.btn_patch_all)

        # Verify Button
        self.btn_verify = QPushButton("ตรวจสอบความถูกต้องของ Firmware หลัง Patch")
        self.btn_verify.clicked.connect(self.verify_firmware)
        main_layout.addWidget(self.btn_verify)

        # Info Button
        self.btn_fw_info = QPushButton("ตรวจสอบ / วิเคราะห์รายละเอียด Firmware")
        self.btn_fw_info.clicked.connect(self.show_fw_info)
        main_layout.addWidget(self.btn_fw_info)

        # Tabs (Log/Info)
        main_layout.addWidget(self.tabs)

        # File select
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

    def patch_boot_delay(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        delay = self.delay_combo.currentText()
        base = os.path.basename(self.fw_path)
        out_file = os.path.join(self.output_dir, f"patched_delay_{delay}_{base}")
        args = [self.toolkit_path, "patch", "--input", self.fw_path, "--output", out_file, "--bootdelay", delay]
        self._run_toolkit(args, patched_out=out_file)

    def patch_shell_serial(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        base = os.path.basename(self.fw_path)
        out_file = os.path.join(self.output_dir, f"patched_serial_{base}")
        args = [
            self.toolkit_path, "patch-rootfs0-services",
            "--input", self.fw_path, "--output", out_file,
            "--ports", "ttyS1", "--remove-others"
        ]
        self._run_toolkit(args, patched_out=out_file)

    def patch_shell_network(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        base = os.path.basename(self.fw_path)
        out_file = os.path.join(self.output_dir, f"patched_network_{base}")
        args = [
            self.toolkit_path, "patch-rootfs0-services",
            "--input", self.fw_path, "--output", out_file,
            "--ports", "ttyS1", "--remove-others",
            "--enable-telnet", "--telnet-port", "23",
            "--enable-ftp", "--ftp-port", "21", "--ftp-root", "/"
        ]
        self._run_toolkit(args, patched_out=out_file)

    def patch_all(self):
        # เริ่มจากไฟล์ต้นฉบับ input
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        delay = self.delay_combo.currentText()
        base = os.path.basename(self.fw_path)
        # 1. Patch boot delay
        delay_out = os.path.join(self.output_dir, f"patched_delay_{delay}_{base}")
        args_delay = [self.toolkit_path, "patch", "--input", self.fw_path, "--output", delay_out, "--bootdelay", delay]
        def after_delay():
            # 2. Patch shell serial ต่อจากไฟล์ boot delay
            serial_out = os.path.join(self.output_dir, f"patched_serial_{delay}_{base}")
            args_serial = [
                self.toolkit_path, "patch-rootfs0-services",
                "--input", delay_out, "--output", serial_out,
                "--ports", "ttyS1", "--remove-others"
            ]
            def after_serial():
                # 3. Patch shell network ต่อจากไฟล์ serial
                net_out = os.path.join(self.output_dir, f"patched_all_{delay}_{base}")
                args_net = [
                    self.toolkit_path, "patch-rootfs0-services",
                    "--input", serial_out, "--output", net_out,
                    "--ports", "ttyS1", "--remove-others",
                    "--enable-telnet", "--telnet-port", "23",
                    "--enable-ftp", "--ftp-port", "21", "--ftp-root", "/"
                ]
                self._run_toolkit(args_net, patched_out=net_out)
            self._run_toolkit(args_serial, patched_out=serial_out, callback=after_serial)
        self._run_toolkit(args_delay, patched_out=delay_out, callback=after_delay)

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