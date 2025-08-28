import sys, subprocess, threading
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton, 
    QTextEdit, QFileDialog, QLabel, QComboBox, QHBoxLayout, QMessageBox
)
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(800, 600)
        self.fw_path = None
        self.patched_fw = None

        # Layout
        central = QWidget()
        main_layout = QVBoxLayout(central)

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

        # Log Output (Real-time)
        main_layout.addWidget(QLabel("Log Output (Real-time):"))
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        main_layout.addWidget(self.log_view)

        # File select
        self.btn_select_fw = QPushButton("เลือกไฟล์ Firmware")
        self.btn_select_fw.clicked.connect(self.select_firmware)
        main_layout.addWidget(self.btn_select_fw)

        self.setCentralWidget(central)

    def log(self, text):
        self.log_view.append(text)
        self.log_view.ensureCursorVisible()

    def select_firmware(self):
        file, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์เฟิร์มแวร์")
        if file:
            self.fw_path = file
            self.patched_fw = None
            self.log(f"เลือกไฟล์: {file}")

    def _run_toolkit(self, args, patched_out=None):
        # Run toolkit as subprocess, show log real-time
        def worker():
            self.log(f"เรียก {' '.join(args)}")
            proc = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            out = ""
            for line in iter(proc.stdout.readline, ""):
                self.log(line.strip())
                out += line
            proc.stdout.close()
            proc.wait()
            if proc.returncode == 0:
                self.log("✅ เสร็จสมบูรณ์")
                if patched_out:
                    self.patched_fw = patched_out
            else:
                self.log("❌ พบข้อผิดพลาด")

        threading.Thread(target=worker, daemon=True).start()

    def patch_boot_delay(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        delay = self.delay_combo.currentText()
        out_file, _ = QFileDialog.getSaveFileName(self, "บันทึกไฟล์ที่ Patch แล้ว", "patched_delay.bin")
        if not out_file:
            return
        # เรียก toolkit: ./firmware_toolkit.sh patch --input fw.bin --output out.bin --bootdelay X
        args = ["./firmware_toolkit.sh", "patch", "--input", self.fw_path, "--output", out_file, "--bootdelay", delay]
        self._run_toolkit(args, patched_out=out_file)

    def patch_shell_serial(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        out_file, _ = QFileDialog.getSaveFileName(self, "บันทึกไฟล์ที่ Patch แล้ว", "patched_serial.bin")
        if not out_file:
            return
        # เรียก toolkit: ./firmware_toolkit.sh patch-rootfs0-services --input fw.bin --output out.bin --ports ttyS1 --remove-others
        args = [
            "./firmware_toolkit.sh", "patch-rootfs0-services",
            "--input", self.fw_path, "--output", out_file,
            "--ports", "ttyS1", "--remove-others"
        ]
        self._run_toolkit(args, patched_out=out_file)

    def patch_shell_network(self):
        if not self.fw_path:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        out_file, _ = QFileDialog.getSaveFileName(self, "บันทึกไฟล์ที่ Patch แล้ว", "patched_network.bin")
        if not out_file:
            return
        # toolkit: เพิ่ม telnet/ftp
        args = [
            "./firmware_toolkit.sh", "patch-rootfs0-services",
            "--input", self.fw_path, "--output", out_file,
            "--ports", "ttyS1", "--remove-others",
            "--enable-telnet", "--telnet-port", "23",
            "--enable-ftp", "--ftp-port", "21", "--ftp-root", "/"
        ]
        self._run_toolkit(args, patched_out=out_file)

    def verify_firmware(self):
        fw = self.patched_fw or self.fw_path
        if not fw:
            QMessageBox.warning(self, "ยังไม่ได้เลือกไฟล์", "กรุณาเลือกไฟล์ firmware ก่อน")
            return
        args = ["./firmware_toolkit.sh", "verify-rootfs", "--input", fw, "--index", "0", "--port", "ttyS1"]
        self._run_toolkit(args, patched_out=None)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())