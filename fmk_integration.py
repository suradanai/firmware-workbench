import os, subprocess, shutil, re, tempfile

class FMKError(Exception):
    pass

# -------------------------------------------------
# Path / FMK location
# -------------------------------------------------
def locate_fmk(explicit_path=None):
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

# -------------------------------------------------
# Config parser
# -------------------------------------------------
def parse_config(config_path):
    """
    Parse config.log (simple KEY='VALUE' lines). For multi-squash top file it may also contain
    raw lines that point to segment directories (no '=').
    We return (meta_dict, extra_lines)
    """
    meta = {}
    extra = []
    if not os.path.isfile(config_path):
        return meta, extra
    with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            if "=" not in line:
                extra.append(line)
                continue
            k,v=line.split("=",1)
            v=v.strip().strip("'").strip('"')
            meta[k.strip()] = v
    # convert numeric fields
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
    return meta, extra

# -------------------------------------------------
# Run command
# -------------------------------------------------
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

# -------------------------------------------------
# Single-firmware extract / build
# -------------------------------------------------
def extract_firmware(fmk_root, firmware_path, workspace_dir, log_callback=None, use_sudo="auto"):
    if not os.path.isdir(fmk_root):
        raise FMKError("FMK root not found.")
    script = os.path.join(fmk_root,"extract-firmware.sh")
    ensure_executable(script)
    if not os.path.isfile(firmware_path):
        raise FMKError("Firmware file not found.")
    if os.path.exists(workspace_dir):
        raise FMKError(f"Workspace already exists: {workspace_dir}")
    os.makedirs(os.path.dirname(workspace_dir), exist_ok=True)
    sudo_flag = (use_sudo is True)
    run_cmd([script, firmware_path, workspace_dir], cwd=fmk_root, log_callback=log_callback, use_sudo=sudo_flag)
    config_path = os.path.join(workspace_dir,"logs","config.log")
    meta, _ = parse_config(config_path)
    return meta

def build_firmware(fmk_root, workspace_dir, nopad=False, minblk=False,
                   log_callback=None, use_sudo="auto"):
    script = os.path.join(fmk_root,"build-firmware.sh")
    ensure_executable(script)
    if not os.path.isdir(workspace_dir):
        raise FMKError("Workspace not found.")
    args = [script, workspace_dir]
    if nopad:
        args.append("-nopad")
    elif minblk:
        args.append("-min")
    sudo_flag = (use_sudo is True)
    run_cmd(args, cwd=fmk_root, log_callback=log_callback, use_sudo=sudo_flag)
    out_path = os.path.join(workspace_dir, "new-firmware.bin")
    return out_path if os.path.isfile(out_path) else None

# -------------------------------------------------
# Multi-squash extract / build
# -------------------------------------------------
def extract_multisquash(fmk_root, firmware_path, workspace_dir, log_callback=None):
    """
    Uses extract-multisquashfs-firmware.sh which:
      - Creates main workspace_dir
      - Writes segment directory paths (one per line) into logs/config.log
      - Each segment path has its own logs/config.log with KEY=VAL pairs.
    Returns: list of segment dict:
        {
          'segment_dir': <path>,
          'meta': <dict>,
          'name': <basename of segment_dir>
        }
    """
    script = os.path.join(fmk_root,"extract-multisquashfs-firmware.sh")
    ensure_executable(script)
    if os.path.exists(workspace_dir):
        raise FMKError(f"Workspace already exists: {workspace_dir}")
    run_cmd([script, firmware_path, workspace_dir], cwd=fmk_root, log_callback=log_callback)
    # parse main config for segment dirs
    top_config = os.path.join(workspace_dir,"logs","config.log")
    _, extra_lines = parse_config(top_config)
    segments = []
    for line in extra_lines:
        # Expect line is an absolute path to segment workspace
        seg_dir = line.strip()
        if not os.path.isdir(seg_dir):
            continue
        seg_conf = os.path.join(seg_dir,"logs","config.log")
        meta, _ = parse_config(seg_conf)
        segments.append({
            "segment_dir": seg_dir,
            "meta": meta,
            "name": os.path.basename(seg_dir)
        })
    if not segments:
        raise FMKError("No squashfs segments detected in multi-squash extraction.")
    return segments

def build_multisquash(fmk_root, workspace_dir, nopad=False, minblk=False,
                      log_callback=None):
    script = os.path.join(fmk_root,"build-multisquashfs-firmware.sh")
    ensure_executable(script)
    args = [script, workspace_dir]
    # (Original script only accepts -nopad or -min? We mimic same semantics)
    if nopad:
        args.append("-nopad")
    elif minblk:
        args.append("-min")
    run_cmd(args, cwd=fmk_root, log_callback=log_callback)
    out_path = os.path.join(workspace_dir, "new-firmware.bin")
    return out_path if os.path.isfile(out_path) else None

# -------------------------------------------------
# IPK management
# -------------------------------------------------
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

# -------------------------------------------------
# Vendor post-process (Linksys footer example)
# -------------------------------------------------
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
    h = meta.get("HEADER_TYPE","").lower()
    footer = meta.get("FOOTER_SIZE",0)
    return footer>0 and any(x in h for x in ["trx","uimage","hdr0","linksys"])

# -------------------------------------------------
# Size / Space estimation
# -------------------------------------------------
def compute_original_rootfs_span(meta):
    """
    Returns maximum bytes available for rootfs in the original image (excluding footer)
    span = (FOOTER_OFFSET - FS_OFFSET - FOOTER_SIZE)
    """
    fs_offset = meta.get("FS_OFFSET")
    footer_off = meta.get("FOOTER_OFFSET", meta.get("FW_SIZE",0))
    footer_size = meta.get("FOOTER_SIZE",0)
    if fs_offset is None or footer_off == 0:
        return None
    return footer_off - fs_offset - footer_size

def estimate_squashfs_size(rootfs_dir, meta, log_callback=None):
    """
    Predict compressed size by actually running mksquashfs to a temp file (then remove).
    We try to honor FS_BLOCKSIZE, FS_ARGS, FS_COMPRESSION heuristics.
    """
    mkfs_path = meta.get("MKFS","").strip('"').strip("'")
    if not mkfs_path:
        # fallback
        mkfs_path = shutil.which("mksquashfs")
    if not mkfs_path or not os.path.isfile(mkfs_path):
        raise FMKError("Cannot locate mksquashfs (MKFS not found).")
    ensure_executable(mkfs_path)

    blocksize = meta.get("FS_BLOCKSIZE")
    fs_args = meta.get("FS_ARGS","")
    comp = meta.get("FS_COMPRESSION","")

    cmd = [mkfs_path, rootfs_dir]
    tmp_fd, tmp_out = tempfile.mkstemp(prefix="sqfs-est-", suffix=".img")
    os.close(tmp_fd)
    cmd.append(tmp_out)
    # Always use -noappend for prediction
    cmd.append("-noappend")
    if blocksize:
        cmd += ["-b", str(blocksize)]
    if comp in ("lzma","xz","gzip"):
        cmd += ["-comp", comp]
    if fs_args:
        for token in fs_args.split():
            cmd.append(token)

    # minimal root option
    if "-all-root" not in cmd:
        cmd.append("-all-root")

    if log_callback:
        log_callback(f"[FMK] Predict size via: {' '.join(cmd)}")

    # Run
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        if log_callback:
            log_callback("[FMK] Predict mksquashfs failed, fallback to raw folder size")
        try:
            os.remove(tmp_out)
        except OSError:
            pass
        return folder_size_bytes(rootfs_dir)

    size = os.path.getsize(tmp_out)
    try:
        os.remove(tmp_out)
    except OSError:
        pass
    return size

def folder_size_bytes(path):
    total=0
    for root,dirs,files in os.walk(path):
        for f in files:
            try:
                fp=os.path.join(root,f)
                total+=os.path.getsize(fp)
            except:
                pass
    return total