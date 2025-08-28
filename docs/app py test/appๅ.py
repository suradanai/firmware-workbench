import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QTextEdit, QFileDialog, QVBoxLayout, QWidget

import subprocess

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firmware Workbench")
        self.resize(700, 400)
        layout = QVBoxLayout()
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        btn_binwalk = QPushButton("เลือกไฟล์แล้ว Scan ด้วย Binwalk")
        btn_binwalk.clicked.connect(self.run_binwalk)
        btn_toolkit = QPushButton("เลือกไฟล์แล้ว Patch ด้วย Toolkit")
        btn_toolkit.clicked.connect(self.run_toolkit)
        layout.addWidget(btn_binwalk)
        layout.addWidget(btn_toolkit)
        layout.addWidget(self.text)
        w = QWidget()
        w.setLayout(layout)
        self.setCentralWidget(w)

    def run_binwalk(self):
        file, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์เฟิร์มแวร์")
        if file:
            self.text.append(f"กำลังสแกน: {file}")
            result = subprocess.run(["binwalk", file], capture_output=True, text=True)
            self.text.append(result.stdout)

    def run_toolkit(self):
        file, _ = QFileDialog.getOpenFileName(self, "เลือกไฟล์เฟิร์มแวร์ (Toolkit)")
        if file:
            self.text.append(f"กำลังรัน toolkit: {file}")
            # ใส่ path ของ firmware_toolkit.sh ที่คุณมีจริง
            toolkit_path = "./firmware_toolkit.sh"
            result = subprocess.run([toolkit_path, "show-layout", "--input", file], capture_output=True, text=True)
            self.text.append(result.stdout)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())