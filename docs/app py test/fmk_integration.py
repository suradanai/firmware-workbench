import os, subprocess, shutil, time, re, threading

class FMKError(Exception):
    pass

def locate_fmk(explicit_path=None):
    """
    ลำดับความพยายามค้นหา FMK:
    1. explicit_path (argument)
    2. ENV: FMK_PATH
    3. config.yaml (อ่านภายนอกจาก app.py – ที่นี่ให้ caller ส่ง explicit เข้ามาถ้าต้อง)
    4. relative paths: ./external/firmware_mod_kit , ./firmware_mod_kit
    5. /opt/firmware-mod-kit
    """
    candidates = []
    if explicit_path:
        candidates.append(explicit_path)
    env = os.environ.get("FMK_PATH")
    if env:
        candidates.append(env)
    candidates += [
        "external/firmware_mod_kit",
        "firmware_mod_kit",
        "/opt/firmware-mod-kit",
    ]
    for c in candidates:
        p = os.path.abspath(c)
        if os.path.isdir(p) and os.path.isfile(os.path.join(p, "extract-firmware.sh")):
            return p
    return None

def ensure_executable(path):
    if os.path.exists(path):
        try:
            os.chmod(path, 0o755)
        except Exception:
            pass

def parse_config(config_path):
    meta = {}
    if not os.path.isfile(config_path):
        return meta
    with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line or "=" not in line: continue
            k,v=line.split("=",1)
            v=v.strip().strip("'").strip('"')
            meta[k.strip()] = v
    int_keys = ["FW_SIZE","HEADER_SIZE","HEADER_IMAGE_SIZE","FOOTER_SIZE",
                "FOOTER_OFFSET","FS_OFFSET","FS_BLOCKSIZE"]
    for k in int_keys:
        if k in meta:
            val = meta[k]
            try:
                if isinstance(val,str) and val.lower().startswith("0x"):
                    meta[k]=int(val,16)
                else:
                    meta[k]=int(val)
            except:
                pass
    return meta

def run_cmd(cmd, cwd=None, log_callback=None, use_sudo=False, check=True):
    if use_sudo and os.geteuid()!=0 and shutil.which("sudo"):
        cmd = ["sudo"] + cmd
    if log_callback:
        log_callback(f"[FMK] RUN: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=cwd)
    for line in proc.stdout:
        if log_callback:
            log_callback(line.rstrip())
    proc.wait()
    if check and proc.returncode!=0:
        raise FMKError(f"Command failed: {' '.join(cmd)} (rc={proc.returncode})")
    return proc.returncode

def extract_firmware(fmk_root, firmware_path, workspace_dir, log_callback=None, use_sudo="auto"):
    """
    เรียก extract-firmware.sh
    use_sudo: 'auto' | True | False
    """
    if not os.path.isdir(fmk_root):
        raise FMKError("FMK root not found.")
    script = os.path.join(fmk_root,"extract-firmware.sh")
    ensure_executable(script)
    if not os.path.isfile(firmware_path):
        raise FMKError("Firmware file not found.")
    if os.path.exists(workspace_dir):
        raise FMKError(f"Workspace already exists: {workspace_dir}")
    os.makedirs(os.path.dirname(workspace_dir), exist_ok=True)

    sudo_flag = False
    if use_sudo=="auto":
        # heuristic: ถ้าต้องเจอ jffs2/yaffs2 ต้องใช้ root เพื่อสร้าง device node (ตรวจหลัง extract ก็ได้)
        sudo_flag = False
    elif use_sudo is True:
        sudo_flag = True

    run_cmd([script, firmware_path, workspace_dir], cwd=fmk_root, log_callback=log_callback, use_sudo=sudo_flag)

    config_path = os.path.join(workspace_dir,"logs","config.log")
    meta = parse_config(config_path)
    return meta

def build_firmware(fmk_root, workspace_dir, nopad=False, minblk=False, log_callback=None, use_sudo="auto"):
    script = os.path.join(fmk_root,"build-firmware.sh")
    ensure_executable(script)
    if not os.path.isdir(workspace_dir):
        raise FMKError("Workspace not found.")
    args = [script, workspace_dir]
    if nopad:
        args.append("-nopad")
    elif minblk:
        args.append("-min")
    sudo_flag = False
    if use_sudo=="auto":
        sudo_flag = False
    elif use_sudo is True:
        sudo_flag = True
    run_cmd(args, cwd=fmk_root, log_callback=log_callback, use_sudo=sudo_flag)
    # output new firmware path:
    out_path = os.path.join(workspace_dir, "new-firmware.bin")
    return out_path if os.path.isfile(out_path) else None

def install_ipk(fmk_root, workspace_dir, ipk_path, log_callback=None):
    script = os.path.join(fmk_root,"ipkg_install.sh")
    ensure_executable(script)
    if not os.path.isfile(ipk_path):
        raise FMKError("IPK file missing.")
    run_cmd([script, ipk_path, workspace_dir], cwd=fmk_root, log_callback=log_callback)

def remove_ipk(fmk_root, workspace_dir, ipk_path, log_callback=None):
    script = os.path.join(fmk_root,"ipkg_remove.sh")
    ensure_executable(script)
    if not os.path.isfile(ipk_path):
        raise FMKError("IPK file missing.")
    run_cmd([script, ipk_path, workspace_dir], cwd=fmk_root, log_callback=log_callback)

def postprocess_linksys_footer(fmk_root, firmware_path, log_callback=None):
    script = os.path.join(fmk_root,"linksys_footer.sh")
    if not os.path.isfile(script):
        if log_callback:
            log_callback("[FMK] Linksys footer script not found, skip.")
        return None
    ensure_executable(script)
    run_cmd([script, firmware_path], cwd=fmk_root, log_callback=log_callback)
    out_mod = os.path.join(os.getcwd(), "modified_checksum.img")
    if os.path.isfile(out_mod):
        return out_mod
    return None

def detect_linksys_candidate(meta):
    # heuristic: HEADER_TYPE contains 'trx' หรือ 'uimage' และ FOOTER_SIZE > 0
    h = meta.get("HEADER_TYPE","").lower()
    footer = meta.get("FOOTER_SIZE",0)
    return footer>0 and any(x in h for x in ["trx","uimage","hdr0","linksys"])