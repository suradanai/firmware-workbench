import sys, os, subprocess, threading, hashlib, struct, shutil
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, 
    QTextEdit, QFileDialog, QLabel, QComboBox, QHBoxLayout, QMessageBox, QTabWidget, QLineEdit
)
from PySide6.QtCore import Qt, Signal, QObject

# ... (ฟังก์ชัน utility ทั้งหมดตามเดิม)

class LogEmitter(QObject):
    log_signal = Signal(str)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(950, 750)
        self.fw_path = None
        self.patched_fw = None
        self.output_dir = os.path.abspath("output")
        os.makedirs(self.output_dir, exist_ok=True)

        self.toolkit_path = os.path.abspath("firmware_toolkit.sh")
        if os.path.exists(self.toolkit_path):
            os.chmod(self.toolkit_path, 0o755)

        # Log signal emitter
        self.log_emitter = LogEmitter()
        self.log_emitter.log_signal.connect(self.log)

        # ... (UI layout ทั้งหมดเหมือนเดิม)

        # Main layout
        central = QWidget()
        main_layout = QVBoxLayout(central)

        # Output folder controls
        out_layout = QHBoxLayout()
        out_layout.addWidget(QLabel("Output folder:"))
        self.output_edit = QLineEdit(self.output_dir)
        out_layout.addWidget(self.output_edit)
        self.btn_select_output = QPushButton("เลือกโฟลเดอร์ Output")
        self.btn_select_output.clicked.connect(self.select_output_folder)
        out_layout.addWidget(self.btn_select_output)
        main_layout.addLayout(out_layout)

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

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "เลือกโฟลเดอร์ Output", self.output_dir)
        if folder:
            self.output_dir = folder
            self.output_edit.setText(folder)
            os.makedirs(self.output_dir, exist_ok=True)

    def select_firmware(self):
        file, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์เฟิร์มแวร์")
        if file:
            self.fw_path = file
            self.patched_fw = None
            base = os.path.basename(file)
            dest = os.path.join(self.output_dir, f"original_{base}")
            if not os.path.exists(dest):
                shutil.copy2(file, dest)
                self.log(f"สำเนา firmware ดั้งเดิมไว้ที่: {dest}")
            else:
                self.log(f"พบ original firmware ที่: {dest}")
            self.fw_path = dest
            self.log(f"เลือกไฟล์: {self.fw_path}")

    def _run_toolkit(self, args, patched_out=None):
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
                else:
                    self.log_emitter.log_signal.emit("❌ พบข้อผิดพลาด")
            except Exception as e:
                self.log_emitter.log_signal.emit(f"❌ {e}")
        threading.Thread(target=worker, daemon=True).start()

    # ... (ที่เหลือเหมือนเดิมทุกอย่าง)
    # patch_boot_delay, patch_shell_serial, patch_shell_network, verify_firmware, show_fw_info
    # ไม่ต้องเปลี่ยน logic ใดๆ

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())