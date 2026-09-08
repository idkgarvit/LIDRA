"""
LIDRA XDP Loader — loads pre-compiled xdp_drop.o via raw bpf() syscall.

Bypasses libbpf entirely: parses the ELF object, creates maps via bpf()
syscall, patches map FDs into BPF instructions, loads the program, and
attaches via /sbin/ip.

Since BPF map FDs are process-scoped, the loader process acts as a
Unix-socket IPC server: block/unblock/status commands connect to the
running loader and get processed there.

Usage:
  # Load and attach XDP (daemonizes to keep maps alive):
  sudo python3 xdp_loader.py load eth0

  # Block/unblock IPs while loader is running:
  sudo python3 xdp_loader.py block 1.2.3.4
  sudo python3 xdp_loader.py unblock 1.2.3.4

  # Show stats / status:
  sudo python3 xdp_loader.py status

  # Detach and stop:
  sudo python3 xdp_loader.py unload eth0
  sudo python3 xdp_loader.py stop
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import signal
import socket
import struct
import subprocess
import sys
from pathlib import Path

# ================================================================
# bpf() syscall via ctypes
# ================================================================

__NR_bpf = 321  # x86_64

BPF_MAP_CREATE        = 0
BPF_MAP_LOOKUP_ELEM   = 1
BPF_MAP_UPDATE_ELEM   = 2
BPF_MAP_DELETE_ELEM   = 3
BPF_PROG_LOAD         = 5
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_LINK_CREATE       = 28

BPF_MAP_TYPE_HASH         = 1
BPF_MAP_TYPE_PERCPU_HASH  = 5
BPF_MAP_TYPE_PERCPU_ARRAY = 6

BPF_PROG_TYPE_XDP = 6

BPF_XDP = 4  # link_type = BPF_XDP for link_create
BPF_XDP_ATTACHED = 4  # attach_type = BPF_XDP (same value)
BPF_F_REPLACE = 4

BPF_ANY = 0


# ---------------------------------------------------------------
# bpf_attr variants for each bpf() command
# The kernel's union bpf_attr uses different field layouts for
# each command.  We define separate ctypes structures with the
# correct offsets for the fields each command actually reads.
# ---------------------------------------------------------------

class _MapCreateAttr(ctypes.Structure):
    """Fields for BPF_MAP_CREATE."""
    _fields_ = [
        ("map_type",     ctypes.c_uint32),
        ("key_size",     ctypes.c_uint32),
        ("value_size",   ctypes.c_uint32),
        ("max_entries",  ctypes.c_uint32),
        ("map_flags",    ctypes.c_uint32),
    ]


class _ProgLoadAttr(ctypes.Structure):
    """Fields for BPF_PROG_LOAD.
    Must be 8-byte aligned for insns/license/log_buf pointers."""
    _fields_ = [
        ("prog_type",   ctypes.c_uint32),
        ("insn_cnt",    ctypes.c_uint32),
        ("insns",       ctypes.c_uint64),
        ("license",     ctypes.c_uint64),
        ("log_level",   ctypes.c_uint32),
        ("log_size",    ctypes.c_uint32),
        ("log_buf",     ctypes.c_uint64),
        ("kern_version", ctypes.c_uint32),
        ("prog_flags",  ctypes.c_uint32),
    ]


class _MapOpAttr(ctypes.Structure):
    """Fields for BPF_MAP_LOOKUP_ELEM / UPDATE_ELEM / DELETE_ELEM."""
    _fields_ = [
        ("map_fd",      ctypes.c_uint32),
        ("_pad",        ctypes.c_uint32),  # padding for 8-byte alignment
        ("key",         ctypes.c_uint64),
        ("value",       ctypes.c_uint64),
        ("flags",       ctypes.c_uint64),
    ]


class _LinkCreateAttr(ctypes.Structure):
    """Fields for BPF_LINK_CREATE (XDP attach, kernel 5.7+)."""
    _fields_ = [
        ("link_type",            ctypes.c_uint32),
        ("link_flags",           ctypes.c_uint32),
        ("link_prog_fd",         ctypes.c_uint32),
        ("link_target_ifindex",  ctypes.c_uint32),
        ("link_attach_type",     ctypes.c_uint32),
        ("link_create_flags",    ctypes.c_uint32),
    ]


class _GetProgInfoAttr(ctypes.Structure):
    """Fields for BPF_OBJ_GET_INFO_BY_FD."""
    _fields_ = [
        ("info_prog_fd", ctypes.c_uint32),
        ("_pad0",        ctypes.c_uint32),
        ("info_info",    ctypes.c_uint64),
        ("info_info_len", ctypes.c_uint64),
    ]


# Tag of the compiled xdp_drop.o program (deterministic from bytecode)
XDP_TAG = "b1e84bda33025a37"


def link_create_xdp(prog_fd: int, ifindex: int) -> int:
    """Attach XDP via BPF_LINK_CREATE (kernel 5.7+).

    bpf_attr layout for LINK_CREATE:
        link_type:       u32 (BPF_XDP=4)
        link_create_flags: u32
        prog_fd:         u32
        target_ifindex:  u32
        attach_type:     u32 (BPF_XDP=4)
        flags:           u32
    """
    attr = _LinkCreateAttr()
    attr.link_type = BPF_XDP
    attr.link_prog_fd = prog_fd
    attr.link_target_ifindex = ifindex
    attr.link_attach_type = BPF_XDP_ATTACHED
    ret = _libc.syscall(__NR_bpf, BPF_LINK_CREATE,
                        ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret


__NR_bpf = 321  # x86_64

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
# Set argtypes so 64-bit pointers aren't truncated to 32-bit int
_libc.syscall.argtypes = [ctypes.c_long, ctypes.c_long,
                           ctypes.c_void_p, ctypes.c_long]
_libc.syscall.restype = ctypes.c_long


def create_map(map_type: int, key_size: int, value_size: int,
               max_entries: int, map_flags: int = 0) -> int:
    attr = _MapCreateAttr()
    attr.map_type = map_type
    attr.key_size = key_size
    attr.value_size = value_size
    attr.max_entries = max_entries
    attr.map_flags = map_flags
    ret = _libc.syscall(__NR_bpf, BPF_MAP_CREATE,
                        ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return ret


def map_update_elem(map_fd: int, key: bytes, value: bytes):
    k = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
    v = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
    attr = _MapOpAttr()
    attr.map_fd = map_fd
    attr.key = ctypes.addressof(k)
    attr.value = ctypes.addressof(v)
    attr.flags = BPF_ANY
    ret = _libc.syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM,
                        ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def map_lookup_elem(map_fd: int, key: bytes, value_size: int) -> bytes | None:
    k = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
    v = (ctypes.c_ubyte * value_size)()
    attr = _MapOpAttr()
    attr.map_fd = map_fd
    attr.key = ctypes.addressof(k)
    attr.value = ctypes.addressof(v)
    ret = _libc.syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM,
                        ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        if err == 2:  # ENOENT — key not found
            return None
        raise OSError(err, os.strerror(err))
    return bytes(v)


def map_delete_elem(map_fd: int, key: bytes):
    k = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
    attr = _MapOpAttr()
    attr.map_fd = map_fd
    attr.key = ctypes.addressof(k)
    ret = _libc.syscall(__NR_bpf, BPF_MAP_DELETE_ELEM,
                        ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def load_xdp_prog(insns: bytes, insn_count: int) -> int:
    """Load an XDP program. Returns prog_fd."""
    log_buf = ctypes.create_string_buffer(16 * 1024)
    license_bytes = b"GPL"

    attr = _ProgLoadAttr()
    attr.prog_type = BPF_PROG_TYPE_XDP
    attr.insn_cnt = insn_count
    # ponytail: keep buffers referenced until after the syscall — passing
    # .value of a temporary cast dangles (CPython frees it immediately).
    insn_buf = (ctypes.c_ubyte * len(insns)).from_buffer_copy(insns)
    lic_buf = (ctypes.c_ubyte * len(license_bytes)).from_buffer_copy(license_bytes)
    attr.insns = ctypes.cast(insn_buf, ctypes.c_void_p).value
    attr.license = ctypes.cast(lic_buf, ctypes.c_void_p).value
    attr.log_level = 1
    attr.log_size = len(log_buf)
    attr.log_buf = ctypes.addressof(log_buf)
    attr.kern_version = 0

    ret = _libc.syscall(__NR_bpf, BPF_PROG_LOAD,
                        ctypes.byref(attr), ctypes.sizeof(attr))
    if ret < 0:
        err = ctypes.get_errno()
        log_text = log_buf.value.decode(errors="replace") if log_buf.value else ""
        if log_text:
            print(f"  Verifier log:\n{log_text}", file=sys.stderr)
        raise OSError(err, os.strerror(err))
    return ret


# ================================================================
# ELF parsing helpers
# ================================================================

ELF_MAGIC = b'\x7fELF'


def _rd32(data: bytes, off: int) -> int:
    return struct.unpack_from('<I', data, off)[0]


def _rd64(data: bytes, off: int) -> int:
    return struct.unpack_from('<Q', data, off)[0]


def parse_elf(data: bytes) -> dict:
    if data[:4] != ELF_MAGIC:
        raise ValueError("Not an ELF file")
    if data[4] != 2:
        raise ValueError("Only 64-bit ELF supported")

    shoff = _rd64(data, 40)
    shentsize = struct.unpack_from('<H', data, 58)[0]
    shnum = struct.unpack_from('<H', data, 60)[0]
    shstrndx = struct.unpack_from('<H', data, 62)[0]

    # Read all section headers first and collect string tables by index
    sections = []
    strtab_by_idx: dict[int, bytes] = {}

    for i in range(shnum):
        off = shoff + i * shentsize
        sh_name = _rd32(data, off)
        sh_type = _rd32(data, off + 4)
        sh_flags = _rd64(data, off + 8)
        sh_offset = _rd64(data, off + 24)
        sh_size = _rd64(data, off + 32)
        sh_link = _rd32(data, off + 40)
        sh_info = _rd32(data, off + 44)
        sh_addralign = _rd64(data, off + 48)
        sh_entsize = _rd64(data, off + 56)

        # Get name from section string table
        # First, read the shstrtab to decode names
        name = ""

        sec = {
            "name": name, "type": sh_type,
            "flags": sh_flags,
            "offset": sh_offset, "size": sh_size,
            "link": sh_link, "info": sh_info,
            "addralign": sh_addralign, "entsize": sh_entsize,
        }
        sections.append(sec)

        if sh_type == 3:  # SHT_STRTAB
            strtab_by_idx[i] = data[sh_offset:sh_offset + sh_size]

    # Now resolve section names from shstrtab
    shstrtab = strtab_by_idx.get(shstrndx, b"")
    for sec in sections:
        # We need to go back and get sh_name again
        i = sections.index(sec)
        off = shoff + i * shentsize
        sh_name = _rd32(data, off)
        if sh_name > 0 and sh_name < len(shstrtab):
            end = shstrtab.find(b'\x00', sh_name)
            if end >= 0:
                sec["name"] = shstrtab[sh_name:end].decode()

    # Parse symtab
    symtab = []
    for sec in sections:
        if sec["type"] in (2, 11):  # SHT_SYMTAB, SHT_DYNSYM
            entsize = sec["entsize"] if sec["entsize"] > 0 else 24
            count = sec["size"] // entsize
            linked_strtab = strtab_by_idx.get(sec["link"], b"")
            for s in range(count):
                soff = sec["offset"] + s * entsize
                st_name = _rd32(data, soff)
                st_info = data[soff + 4]
                st_shndx = struct.unpack_from('<H', data, soff + 6)[0]
                st_value = _rd64(data, soff + 8)
                st_size = _rd64(data, soff + 16)
                sym_name = ""
                if st_name > 0 and st_name < len(linked_strtab):
                    end = linked_strtab.find(b'\x00', st_name)
                    if end >= 0:
                        sym_name = linked_strtab[st_name:end].decode(errors="replace")
                symtab.append({
                    "name": sym_name, "info": st_info,
                    "shndx": st_shndx, "value": st_value, "size": st_size,
                })
            break

    # Parse relocations
    relocs = []
    for sec in sections:
        if sec["type"] == 9:  # SHT_REL
            entsize = sec["entsize"] if sec["entsize"] > 0 else 16  # Elf64_Rel
            count = sec["size"] // entsize
            for r in range(count):
                roff = sec["offset"] + r * entsize
                r_offset = _rd64(data, roff)
                r_info = _rd64(data, roff + 8)
                sym_idx = r_info >> 32
                r_type_val = r_info & 0xffffffff
                relocs.append({
                    "target_sec": sec["info"],
                    "offset": r_offset,
                    "sym_idx": sym_idx,
                    "type": r_type_val,
                })

    return {
        "sections": sections,
        "symtab": symtab,
        "relocs": relocs,
        "shstrtab": shstrtab,
    }


# ================================================================
# Map definitions matching xdp_drop.c
# ================================================================

MAP_DEFS = [
    {"name": "blocklist",  "type": BPF_MAP_TYPE_HASH,
     "key_size": 4, "value_size": 1, "max_entries": 100000},
    {"name": "rate_limit", "type": BPF_MAP_TYPE_PERCPU_HASH,
     "key_size": 4, "value_size": 8, "max_entries": 10000},
    {"name": "stats",      "type": BPF_MAP_TYPE_PERCPU_ARRAY,
     "key_size": 4, "value_size": 8, "max_entries": 1},
]


# ================================================================
# IPC — Unix socket protocol between loader and CLI
# ================================================================

SOCKET_PATH = "/tmp/lidra_xdp.sock"

PROTOCOL_VERSION = 1

REQUEST_BLOCK   = b"BLOCK"
REQUEST_UNBLOCK = b"UNBLK"
REQUEST_STATUS  = b"STATS"
REQUEST_STOP    = b"STOP"
REQUEST_PING    = b"PING"

RESPONSE_OK    = b"OK"
RESPONSE_ERR   = b"ERR"
RESPONSE_DATA  = b"DATA"


def _send_msg(conn: socket.socket, msg_type: bytes, payload: bytes = b""):
    """Send len-prefixed message over socket."""
    header = struct.pack("!4sI", msg_type, len(payload))
    conn.sendall(header + payload)


def _recv_msg(conn: socket.socket, timeout: float = 5.0) -> tuple[bytes, bytes]:
    """Receive len-prefixed message."""
    conn.settimeout(timeout)
    header = conn.recv(8)
    if len(header) < 8:
        raise ConnectionError("Short read on IPC socket")
    msg_type = header[:4]
    payload_len = struct.unpack("!I", header[4:8])[0]
    payload = b""
    while len(payload) < payload_len:
        chunk = conn.recv(payload_len - len(payload))
        if not chunk:
            raise ConnectionError("Connection closed during read")
        payload += chunk
    return msg_type, payload


# ================================================================
# XDP Manager — the actual loading + map operations
# ================================================================

def _validate_ip(ip_str: str) -> bytes | None:
    """Strict IPv4 validation. Returns packed bytes, or None to refuse.

    Refuses loopback (blocking 127.x via XDP is a self-DoS footgun),
    multicast, and unspecified addresses. Private/LAN addresses are
    allowed — blocking local attackers is the point of the blocklist.
    """
    try:
        ip = ipaddress.ip_address((ip_str or "").strip())
    except ValueError:
        return None
    if ip.version != 4 or ip.is_loopback or ip.is_multicast \
            or ip.is_unspecified:
        return None
    return ip.packed


class XDPManager:
    """Manages XDP program lifecycle and map operations."""

    def __init__(self, obj_path: str | Path):
        self.obj_path = Path(obj_path)
        self.data = self.obj_path.read_bytes()
        self.elf = parse_elf(self.data)
        self.prog_fd: int | None = None
        self.link_fd: int | None = None
        self.map_fds: dict[str, int] = {}
        self.iface: str = ""

    # ---------------------------------------------------------------
    # ELF helpers
    # ---------------------------------------------------------------

    def _find_section(self, name: str) -> dict | None:
        for sec in self.elf["sections"]:
            if sec["name"] == name:
                return sec
        return None

    def _section_index(self, name: str) -> int:
        for i, sec in enumerate(self.elf["sections"]):
            if sec["name"] == name:
                return i
        return -1

    # ---------------------------------------------------------------
    # Load
    # ---------------------------------------------------------------

    def load(self) -> bool:
        """Load XDP program and attach to interface."""
        xdp_sec = self._find_section("xdp")
        if not xdp_sec:
            print("ERROR: No 'xdp' section in ELF", file=sys.stderr)
            return False

        # 1. Create maps
        print("Creating maps...")
        fds = []
        for md in MAP_DEFS:
            fd = create_map(md["type"], md["key_size"],
                            md["value_size"], md["max_entries"])
            self.map_fds[md["name"]] = fd
            fds.append(fd)
            print(f"  {md['name']}: fd={fd} (type={md['type']}, "
                  f"key={md['key_size']}, val={md['value_size']}, "
                  f"max={md['max_entries']})")

        # 2. Patch map FDs into BPF instruction immediates
        insns = bytearray(self.data[xdp_sec["offset"]:xdp_sec["offset"] + xdp_sec["size"]])
        insn_count = len(insns) // 8
        xdp_idx = self._section_index("xdp")

        print(f"Patching {len(self.elf['relocs'])} relocations...")
        patched = 0
        for rel in self.elf["relocs"]:
            if rel["target_sec"] != xdp_idx:
                continue
            sym = self.elf["symtab"][rel["sym_idx"]]
            map_name = sym["name"]
            if map_name not in self.map_fds:
                print(f"  WARN: unknown map '{map_name}'", file=sys.stderr)
                continue
            fd = self.map_fds[map_name]
            imm_offset = rel["offset"] + 4
            if imm_offset + 4 > len(insns):
                print(f"  WARN: offset {imm_offset} OOB", file=sys.stderr)
                continue
            struct.pack_into('<i', insns, imm_offset, fd)
            # Set src_reg = BPF_PSEUDO_MAP_FD (1) at byte offset+1
            # byte layout: [dst_reg (low nibble) | src_reg (high nibble)]
            bpf_src_off = rel["offset"] + 1
            if bpf_src_off < len(insns):
                insns[bpf_src_off] |= 0x10  # src_reg = 1
            patched += 1

        print(f"  {patched} relocations patched")

        # 3. Load BPF program
        print(f"Loading program ({insn_count} instructions)...")
        try:
            self.prog_fd = load_xdp_prog(bytes(insns), insn_count)
            print(f"  Program loaded: fd={self.prog_fd}")
        except OSError as e:
            print(f"  Program load FAILED: {e}", file=sys.stderr)
            return False

        return True

    def attach(self, iface: str) -> bool:
        """Attach XDP via bpftool (by program tag)."""
        self.iface = iface

        # First detach any existing XDP on this interface
        subprocess.run(
            ["bpftool", "net", "detach", "xdp", "dev", iface],
            capture_output=True, timeout=10,
        )

        # Attach using bpftool with tag (no need to get prog_id)
        try:
            result = subprocess.run(
                ["bpftool", "net", "attach", "xdp", "tag", XDP_TAG,
                 "dev", iface],
                capture_output=True, timeout=10, text=True,
            )
            if result.returncode == 0:
                print(f"  XDP attached to {iface} via bpftool (tag={XDP_TAG})")
                return True
            stderr = result.stderr.strip()
            print(f"  bpftool attach failed: {stderr}", file=sys.stderr)

            # Retry with explicit id lookup
            if "not found" in stderr or "no such" in stderr:
                result_list = subprocess.run(
                    ["bpftool", "prog", "list", "--json"],
                    capture_output=True, timeout=10, text=True,
                )
                if result_list.returncode == 0:
                    progs = json.loads(result_list.stdout)
                    for p in progs:
                        if p.get("tag") == XDP_TAG:
                            prog_id = p["id"]
                            result2 = subprocess.run(
                                ["bpftool", "net", "attach", "xdp", "id",
                                 str(prog_id), "dev", iface],
                                capture_output=True, timeout=10, text=True,
                            )
                            if result2.returncode == 0:
                                print(f"  XDP attached via bpftool (id={prog_id})")
                                return True
                            print(f"  Retry by id also failed: {result2.stderr.strip()}",
                                  file=sys.stderr)
                            break
        except (OSError, subprocess.TimeoutExpired, FileNotFoundError,
                json.JSONDecodeError) as e:
            print(f"  bpftool attach failed: {e}", file=sys.stderr)

        return False

    def detach(self):
        if self.link_fd is not None:
            try:
                os.close(self.link_fd)
            except OSError:
                pass
            self.link_fd = None
        if self.iface:
            # Also detach via netlink in case of bpftool fallback
            subprocess.run(["/sbin/ip", "link", "set", "dev", self.iface, "xdp", "off"],
                           capture_output=True, timeout=10)

    # ---------------------------------------------------------------
    # Map operations
    # ---------------------------------------------------------------

    def block_ip(self, ip_str: str) -> bool:
        fd = self.map_fds.get("blocklist")
        if fd is None:
            return False
        packed = _validate_ip(ip_str)
        if packed is None:
            return False
        try:
            map_update_elem(fd, packed, b'\x01')
            return True
        except OSError:
            return False

    def unblock_ip(self, ip_str: str) -> bool:
        fd = self.map_fds.get("blocklist")
        if fd is None:
            return False
        packed = _validate_ip(ip_str)
        if packed is None:
            return False
        try:
            map_delete_elem(fd, packed)
            return True
        except OSError:
            return False

    def get_stats(self) -> dict:
        fd = self.map_fds.get("stats")
        if fd is None:
            return {"dropped": -1, "error": "stats map not loaded"}
        try:
            # stats is a PERCPU_ARRAY: one u64 per CPU, concatenated.
            ncpu = os.cpu_count() or 1
            val = map_lookup_elem(fd, b'\x00\x00\x00\x00', 8 * ncpu)
            if val is not None:
                return {"dropped": sum(struct.unpack(f'<{ncpu}Q', val))}
            return {"dropped": 0}
        except (OSError, struct.error) as e:
            return {"dropped": -1, "error": str(e)}

    def cleanup(self):
        for fd in self.map_fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        if self.prog_fd is not None:
            try:
                os.close(self.prog_fd)
            except OSError:
                pass
        self.map_fds.clear()
        self.prog_fd = None


# ================================================================
# IPC Server (runs inside loader process)
# ================================================================

def run_ipc_server(xdp: XDPManager):
    """Unix socket server — handles block/unblock/status from CLI."""
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(5)
    server.settimeout(1.0)  # allow periodic checks

    # Restrict permissions
    os.chmod(SOCKET_PATH, 0o600)

    print(f"  IPC socket: {SOCKET_PATH}")

    running = True
    while running:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            msg_type, payload = _recv_msg(conn, timeout=2.0)
        except (ConnectionError, OSError, TimeoutError):
            conn.close()
            continue

        if msg_type == REQUEST_BLOCK:
            ip = payload.decode()
            ok = xdp.block_ip(ip)
            _send_msg(conn, RESPONSE_OK if ok else RESPONSE_ERR,
                      b"blocked" if ok else b"failed")
            print(f"  [IPC] block {ip}: {'OK' if ok else 'FAIL'}")

        elif msg_type == REQUEST_UNBLOCK:
            ip = payload.decode()
            ok = xdp.unblock_ip(ip)
            _send_msg(conn, RESPONSE_OK if ok else RESPONSE_ERR,
                      b"unblocked" if ok else b"failed")
            print(f"  [IPC] unblock {ip}: {'OK' if ok else 'FAIL'}")

        elif msg_type == REQUEST_STATUS:
            stats = xdp.get_stats()
            data = json.dumps(stats).encode()
            _send_msg(conn, RESPONSE_DATA, data)

        elif msg_type == REQUEST_STOP:
            _send_msg(conn, RESPONSE_OK, b"stopping")
            running = False

        elif msg_type == REQUEST_PING:
            _send_msg(conn, RESPONSE_OK, b"pong")

        else:
            _send_msg(conn, RESPONSE_ERR, b"unknown command")

        conn.close()

    server.close()
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass


# ================================================================
# IPC Client (runs in CLI process)
# ================================================================

def ipc_request(msg_type: bytes, payload: bytes = b"",
                timeout: float = 5.0) -> tuple[bytes, bytes]:
    """Send a request to the running loader's IPC socket."""
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    conn.connect(SOCKET_PATH)
    _send_msg(conn, msg_type, payload)
    resp_type, resp_data = _recv_msg(conn, timeout=timeout)
    conn.close()
    return resp_type, resp_data


# ================================================================
# CLI Commands
# ================================================================

def cmd_load(args: list[str]):
    if not args:
        print("Usage: xdp_loader.py load <iface> [obj-path]", file=sys.stderr)
        sys.exit(1)

    iface = args[0]
    try:
        socket.if_nametoindex(iface)
    except (OSError, AttributeError):
        print(f"ERROR: no such interface: {iface}", file=sys.stderr)
        sys.exit(1)
    if os.geteuid() != 0:
        print("ERROR: XDP load requires root (bpf() + netlink).",
              file=sys.stderr)
        sys.exit(1)
    obj_path = Path(args[1]) if len(args) > 1 else \
        Path(__file__).resolve().parent / "xdp_drop.o"

    if not obj_path.exists():
        print(f"ERROR: {obj_path} not found", file=sys.stderr)
        sys.exit(1)

    # Check if already running
    if os.path.exists(SOCKET_PATH):
        try:
            _, resp = ipc_request(REQUEST_PING, timeout=1.0)
            if resp == b"pong":
                print("ERROR: XDP loader is already running.", file=sys.stderr)
                print(f"  Stop it first: {sys.argv[0]} stop", file=sys.stderr)
                sys.exit(1)
        except (ConnectionError, TimeoutError, FileNotFoundError):
            os.unlink(SOCKET_PATH)

    print(f"Loading XDP from {obj_path}...")
    xdp = XDPManager(obj_path)

    if not xdp.load():
        xdp.cleanup()
        sys.exit(1)

    print(f"Attaching XDP to {iface}...")
    if not xdp.attach(iface):
        # Fail closed: an "armed but unattached" loader would ACK block
        # requests that nothing enforces.
        print("ERROR: attach failed — refusing to run unenforced.",
              file=sys.stderr)
        print(f"  Try manually: /sbin/ip link set dev {iface} xdp obj {obj_path} sec xdp",
              file=sys.stderr)
        xdp.cleanup()
        sys.exit(1)

    print(f"Starting IPC server on {SOCKET_PATH}...")
    print()
    print("Commands (from another terminal):")
    print(f"  sudo python3 {__file__} block 1.2.3.4")
    print(f"  sudo python3 {__file__} unblock 1.2.3.4")
    print(f"  sudo python3 {__file__} status")
    print(f"  sudo python3 {__file__} stop")
    print()
    print("Press Ctrl+C to detach and exit.")

    # Register signal handler
    def shutdown(signum=None, frame=None):
        print("\nShutting down...")
        xdp.detach()
        xdp.cleanup()
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Run IPC server (blocks until STOP or Ctrl+C)
    run_ipc_server(xdp)

    # Clean exit after IPC server stops
    shutdown()


def cmd_unload(args: list[str]):
    iface = args[0] if args else "eth0"

    # Try to stop the loader first
    if os.path.exists(SOCKET_PATH):
        try:
            ipc_request(REQUEST_STOP, timeout=2.0)
        except (ConnectionError, TimeoutError):
            pass

    result = subprocess.run(
        ["/sbin/ip", "link", "set", "dev", iface, "xdp", "off"],
        capture_output=True, timeout=10,
    )
    if result.returncode == 0:
        print(f"XDP detached from {iface}")
    else:
        print(f"Could not detach: {result.stderr.decode(errors='replace')}",
              file=sys.stderr)


def cmd_block(args: list[str]):
    if not args:
        print("Usage: xdp_loader.py block <ip>", file=sys.stderr)
        sys.exit(1)
    ip = args[0]
    try:
        resp_type, resp_data = ipc_request(REQUEST_BLOCK, ip.encode())
        if resp_type == RESPONSE_OK:
            print(f"Blocked {ip}")
        else:
            print(f"Block failed: {resp_data.decode()}", file=sys.stderr)
            sys.exit(1)
    except (ConnectionError, FileNotFoundError) as e:
        print(f"ERROR: Cannot connect to loader: {e}", file=sys.stderr)
        print(f"  Is the loader running? Check {SOCKET_PATH}", file=sys.stderr)
        sys.exit(1)


def cmd_unblock(args: list[str]):
    if not args:
        print("Usage: xdp_loader.py unblock <ip>", file=sys.stderr)
        sys.exit(1)
    ip = args[0]
    try:
        resp_type, resp_data = ipc_request(REQUEST_UNBLOCK, ip.encode())
        if resp_type == RESPONSE_OK:
            print(f"Unblocked {ip}")
        else:
            print(f"Unblock failed: {resp_data.decode()}", file=sys.stderr)
            sys.exit(1)
    except (ConnectionError, FileNotFoundError) as e:
        print(f"ERROR: Cannot connect to loader: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_stop(args: list[str]):
    try:
        resp_type, resp_data = ipc_request(REQUEST_STOP, timeout=3.0)
        print("Loader stopping...")
    except (ConnectionError, FileNotFoundError) as e:
        print(f"Could not connect to loader: {e}", file=sys.stderr)
        # Clean up socket
        try:
            os.unlink(SOCKET_PATH)
        except FileNotFoundError:
            pass
        sys.exit(1)


def cmd_status(args: list[str]):
    try:
        resp_type, resp_data = ipc_request(REQUEST_STATUS)
        if resp_type == RESPONSE_DATA:
            stats = json.loads(resp_data)
            print("XDP Stats:")
            print(f"  Dropped packets: {stats.get('dropped', '?')}")
    except (ConnectionError, FileNotFoundError) as e:
        print(f"Loader not connected: {e}", file=sys.stderr)

    # Also check if any XDP is attached
    result = subprocess.run(
        ["/sbin/ip", "-details", "link", "show"],
        capture_output=True, text=True, timeout=10,
    )
    if "xdp" in result.stdout.lower():
        print("XDP program is attached to an interface.")
        for line in result.stdout.split("\n"):
            if "xdp" in line.lower():
                print(f"  {line.strip()}")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        "load": cmd_load,
        "unload": cmd_unload,
        "block": cmd_block,
        "unblock": cmd_unblock,
        "stop": cmd_stop,
        "status": cmd_status,
    }

    if cmd not in commands:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        print(f"Available: {', '.join(commands.keys())}", file=sys.stderr)
        sys.exit(1)

    commands[cmd](args)


if __name__ == "__main__":
    main()
