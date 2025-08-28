import sys, os, subprocess, threading, hashlib, struct, shutil, tempfile, crypt, random, string
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QTextEdit, QFileDialog, QLabel, QComboBox, QHBoxLayout, QMessageBox, QTabWidget, QLineEdit
)
from PySide6.QtCore import Qt, Signal, QObject

# ... (ฟังก์ชัน utility ทั้งหมดเหมือนเดิม เช่น sha256sum, md5sum, get_partition_details, ...)

# (scan_rootfs_offset_size, analyze_firmware_auto, etc. เหมือนเดิม)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(1300, 850)
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

        # ... (input/output folder controls, scanfs_layout, etc. เหมือนเดิม)

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

        # --- เพิ่ม Patch root password ---
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

    # ... (log, info, select_input_folder, select_output_folder, select_firmware, etc. เหมือนเดิม)

    def get_rootfs_offset_size(self):
        try:
            offset = int(self.rootfs_offset_edit.text(), 16)
            size = int(self.rootfs_size_edit.text(), 16)
            return offset, size
        except Exception as e:
            QMessageBox.warning(self, "RootFS Offset/Size ไม่ถูกต้อง", "กรุณากรอกค่า RootFS Offset/Size ให้ถูกต้อง (เช่น 0x0240000 / 0x03D0000)")
            return None, None

    # ... (auto_detect_rootfs, _run_toolkit, patch_boot_delay, patch_shell_serial, patch_shell_network, patch_all, ai_auto_patch, verify_firmware, show_fw_info เหมือนเดิม)

    # ------------ Patch root password function -------------
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

        # 1. แตก rootfs ออกมา
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

        # 2. สร้าง hash รหัส root ใหม่ (sha512 + salt)
        shadow_path = os.path.join(unsquashfs_dir, "etc", "shadow")
        if not os.path.exists(shadow_path):
            shutil.rmtree(tmpdir)
            self.log("❌ ไม่พบไฟล์ /etc/shadow ใน rootfs")
            QMessageBox.critical(self, "ผิดพลาด", "ไม่พบไฟล์ /etc/shadow ใน rootfs")
            return

        if password == "":
            new_hash = "!"
        else:
            # สร้าง salt
            salt = "".join(random.choices(string.ascii_letters + string.digits, k=16))
            new_hash = crypt.crypt(password, "$6$" + salt)

        # 3. แก้ไขไฟล์ shadow
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
        # เขียนกลับ
        with open(shadow_path, "w") as f:
            for l in new_lines:
                f.write(l if l.endswith("\n") else l + "\n")

        # 4. สร้าง squashfs ใหม่
        new_rootfs_bin = os.path.join(tmpdir, "new_rootfs0.bin")
        try:
            subprocess.check_output(
                ["mksquashfs", unsquashfs_dir, new_rootfs_bin, "-noappend", "-comp", "xz"],
                stderr=subprocess.STDOUT, timeout=60
            )
        except Exception as e:
            shutil.rmtree(tmpdir)
            self.log(f"❌ สร้าง squashfs ไม่สำเร็จ: {e}")
            QMessageBox.critical(self, "ผิดพลาด", f"สร้าง squashfs ไม่สำเร็จ: {e}")
            return

        # 5. เขียน rootfs ใหม่ลงใน firmware ที่ output
        with open(self.fw_path, "rb") as f:
            fw_data = bytearray(f.read())
        with open(new_rootfs_bin, "rb") as f:
            new_rootfs_data = f.read()
        # แทนที่ rootfs เดิม
        fw_data[offset:offset+len(new_rootfs_data)] = new_rootfs_data
        # ถ้ามีขนาดเหลือ ให้ zero fill ต่อท้าย
        if len(new_rootfs_data) < size:
            fw_data[offset+len(new_rootfs_data):offset+size] = b"\x00" * (size - len(new_rootfs_data))
        with open(out_file, "wb") as f:
            f.write(fw_data)

        shutil.rmtree(tmpdir)
        self.log(f"✅ Patch root password สำเร็จ: {out_file}")
        QMessageBox.information(self, "สำเร็จ", f"Patch root password ใน shadow สำเร็จ!\nไฟล์: {out_file}")
        self.patched_fw = out_file

    # ... (ฟังก์ชันอื่น ๆ เหมือนเดิม)

# ... (ส่วน main ไม่เปลี่ยน)
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())