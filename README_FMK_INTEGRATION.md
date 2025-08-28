# FMK Integration + Per-Segment Patch + Diff Viewer + Multi-Segment AI

## ฟีเจอร์ใหม่ (เพิ่มจากเวอร์ชันก่อนหน้า)

1. Patch Root Password / Services ต่อ Segment  
   - ใส่รหัส root ใหม่ (หรือเว้นว่างเพื่อล็อกด้วย !)  
   - Enable Serial Getty (เพิ่มบรรทัด getty ใน /etc/inittab)  
   - Enable Telnet / FTP (เพิ่มใน inetd.conf หรือสร้างสคริปต์ init)  
   - ใช้ได้ทั้งโหมด Single และ Multi-Squash (ดำเนินการกับ segment ที่เลือกในรายการ Segments)

2. Diff Viewer (เปรียบเทียบ rootfs)  
   - สร้าง snapshot rootfs_original อัตโนมัติหลัง Extract  
   - แสดง Added / Removed / Modified  
   - Unified diff ขณะเลือกไฟล์  
   - Export diff (.diff) ได้  
   - ใช้ hash + size ตรวจไฟล์ที่เปลี่ยน

3. Multi-Segment AI รวม  
   - ปุ่ม “วิเคราะห์ทุก Segment (AI ALL)”  
   - วิ่งทีละ segment สรุปผลลงแผง AI  
   - สร้าง summary ความเสี่ยงรวม (ไม่มีรหัส, telnet/ftp เปิด)

4. Predict RootFS Size / Warning  
   - ประเมินขนาด squashfs ใหม่ด้วยการรัน mksquashfs ชั่วคราว  
   - เตือนเมื่อเกิน span เดิม หรือเหลือน้อย (< 64KB)

5. Linksys Footer Fix (ตาม heuristic)  
   - ติ๊กอัตโนมัติเมื่อตรวจพบลักษณะ header/footer ที่อาจใช้

## โครงสร้างไฟล์สำคัญ

```
app.py                # GUI หลัก (ปรับปรุง)
fmk_integration.py    # Wrapper FMK เดิม (ไม่จำเป็นต้องแก้เพิ่มสำหรับฟีเจอร์นี้)
patch_utils.py        # NEW: ฟังก์ชัน patch root password / services
README_FMK_INTEGRATION.md
```

## การใช้งาน Patch Segment

1. Extract (Single หรือ Multi)  
2. เลือก Segment (ถ้า Multi)  
3. ป้อนรหัส root (หรือเว้นว่างเพื่อล็อก)  
4. เลือก Services ที่ต้องการ  
5. กด “Apply Patch to Segment”  
6. เปิด Diff Viewer → Refresh Diff List เพื่อดูการเปลี่ยนแปลง (เช่น /etc/shadow, /etc/inittab, /etc/inetd.conf)

## การใช้งาน Diff Viewer

1. หลัง Extract ระบบสร้าง snapshot: rootfs_original  
2. ปรับแต่ง/patch rootfs  
3. เปิดแท็บ Diff Viewer → Refresh  
4. เลือกไฟล์เพื่อดู unified diff  
5. Export ได้หากต้องการ

## การใช้งาน AI

- วิเคราะห์เฉพาะ segment ที่เลือก: “วิเคราะห์ (AI) สำหรับ segment ที่เลือก/เดี่ยว”
- วิเคราะห์ทุก segment: “วิเคราะห์ทุก Segment (AI ALL)”  
  รายงานรวมจะแสดงทั้งแต่ละ segment และส่วนสรุปความเสี่ยง

## ข้อควรทราบ

- Snapshot rootfs_original เป็นการ copy ทั้งหมด (พื้นที่เพิ่ม) – ถ้าต้องการประหยัดให้เปลี่ยนเป็น hardlink หรือ hashing ในอนาคต  
- การ enable telnet/ftp เป็นแบบ generic (BusyBox) อาจต้องปรับให้เหมาะกับอุปกรณ์จริง  
- หาก firmware ใช้กลไก init พิเศษ (systemd/procd) อาจต้องแก้ logic patch_services  
- Prediction ขนาด squashfs ใช้วิธี build ชั่วคราว จึงใช้เวลา (โดยเฉพาะ blocksize 1MB + xz)  

## Roadmap (ต่อยอด)

- รองรับการเลือกหลาย segment แล้ว patch batch  
- แสดง side-by-side diff (ตอนนี้ unified)  
- ทำ profile (Dev / Harden) auto apply patch  
- Pure Python SquashFS (rebuild_squashfs.py)  
- ระบบ Plugin Vendor (TP-Link, Buffalo)  

## Troubleshooting

| ปัญหา | สาเหตุ | วิธีแก้ |
|-------|--------|---------|
| ไม่เห็น segment list หลัง Extract Multi | ไฟล์ไม่มีหลาย squashfs จริง | ตรวจสอบด้วย binwalk ก่อน |
| Patch root password ล้มเหลว | ไม่มี /etc/shadow | ตรวจสอบ type rootfs หรือสร้างด้วยตนเอง |
| Diff ไม่ขึ้นอะไร | ยังไม่ได้แก้ไฟล์ หรือ snapshot ไม่มี | แก้ไฟล์ แล้วกด Refresh |
| AI rootfs size invalid | meta FS_OFFSET/FOOTER_OFFSET ไม่สมบูรณ์ | ตรวจสอบ config.log |
| Predict error | ไม่พบ mksquashfs/MKFS | ติดตั้ง squashfs-tools หรือแก้ MKFS path |

## Licensing / Credits

อ้างอิงโค้ดแนวคิด FMK (Firmware Mod Kit) ชุดเครื่องมือเดิมโดยผู้พัฒนา Upstream.  
การดัดแปลงเฉพาะส่วน GUI/Wrapper/AI/Diff/Patch ภายใต้โปรเจกต์ของคุณ

Happy firmware hacking!