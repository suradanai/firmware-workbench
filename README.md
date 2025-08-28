# Firmware Workbench

Toolkit สำหรับจัดการ / แตก / แพ็ค / แพตช์ เฟิร์มแวร์ (บูรณาการกับ firmware-mod-kit แบบดึงอัตโนมัติผ่านสคริปต์)

## คุณสมบัติ
- ดึงและอัปเดต firmware-mod-kit เมื่อจำเป็น (ไม่บันเดิลใน repo)
- สคริปต์อัตโนมัติ: `fw-manager.sh` (install / extract / repack)
- รองรับ multi-squashfs, patch utilities, diff helper
- โครงสร้างปรับให้สะอาด: ไม่ commit binary firmware, workspaces, venv

## โครงสร้างหลัก
```
app.py
fw-manager.sh
fmk_integration.py
patch_utils.py
rebuild_squashfs.py
firmware_toolkit.sh
requirements.txt
config.yaml
.gitignore
```

## เริ่มต้นใช้งาน
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./fw-manager.sh install        # จะ clone firmware-mod-kit ไปที่ external/firmware_mod_kit
./fw-manager.sh extract path/to/firmware.bin
```

## หมายเหตุ
- โฟลเดอร์ `external/firmware_mod_kit/` ถูก ignore
- วางไฟล์เฟิร์มแวร์ใน `input/` หรือระบุตรง ๆ ตอนสั่ง extract
- ไม่ควร commit ไฟล์ .bin ลง repo

## License
(ใส่ชนิด ฯลฯ)