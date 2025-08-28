# FMK Integration Guide

## โครงสร้าง
```
firmware-workbench/
  app.py
  fmk_integration.py
  config.yaml
  requirements.txt
  external/
    firmware_mod_kit/   (ซอร์ส FMK)
  workspaces/
  output/
  input/
```

## การเตรียม FMK
1. git clone https://github.com/rampageX/firmware-mod-kit.git external/firmware_mod_kit
2. (อาจต้อง) `cd external/firmware_mod_kit/src && make`
3. ตรวจว่ามี extract-firmware.sh, build-firmware.sh

## config.yaml (ตัวอย่าง)
```yaml
fmk:
  root: external/firmware_mod_kit
  use_sudo_extract: auto
  use_sudo_build: auto
```

## การใช้งานในโปรแกรม
1. แท็บ FMK → เลือก FMK Root (ถ้า auto ไม่เจอ)
2. เลือกไฟล์ Firmware (แท็บ Basic หรือในช่องด้านบน)
3. ตั้งชื่อ Workspace → กด Extract (FMK)
4. ดู metadata (config.log) ใน panel
5. หากติ๊ก Auto Analyze จะรัน AI ทันที
6. ปรับ rootfs ด้วยมือ (ไปแก้ไฟล์ใน workspaces/<ws>/rootfs)
7. ปรับตัวเลือก Build แล้วกด Build Firmware (FMK)
8. Output จะถูกสำเนาไป output/

## IPK Manage
- ใช้ Install IPK => เรียก ipkg_install.sh
- Remove IPK => ipkg_remove.sh (ต้องใช้ IPK เดิมอ้างอิง)

## Vendor Footer
- ถ้า metadata ตรวจเจอ FOOTER_SIZE > 0 และ header pattern → ระบบจะติ๊ก Linksys Footer Fix ให้
- หลัง build จะรัน linksys_footer.sh อัตโนมัติ (ถ้าเลือก)

## หมายเหตุสิทธิ์
- บางระบบไฟล์ระบบ (cramfs/jffs2) ต้องการ sudo ระหว่าง extract/build
- ตั้งใน config.yaml หรือผ่าน environment: FMK_PATH
