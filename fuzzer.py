import argparse
import hashlib
import os
import random
import shutil
import struct
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


BASE_DIR = Path(__file__).resolve().parent

SEED_FILE = BASE_DIR / "config_4"

TARGET_DIR = BASE_DIR
TARGET_EXE = TARGET_DIR / "vuln4.exe"


PASS_AS_ARG_DEFAULT = True
TARGET_FIXED_NAME = "config_4"

DR_BIN32 = Path(r"C:\Users\Huawei\OneDrive\Рабочий стол\учеба\DynamoRIO-Windows-11.3.0-1\bin32")
DRRUN = DR_BIN32 / "drrun.exe"

# лимиты
TIMEOUT_SEC_DEFAULT = 3.0
MAX_ITERS_DEFAULT = 50_000

# выходные папки
OUT_DIR = BASE_DIR / "out"
CRASH_DIR = OUT_DIR / "crashes"
INTERESTING_DIR = OUT_DIR / "interesting"
DRMEM_DIR = OUT_DIR / "drmemory"
LOG_FILE = OUT_DIR / "fuzz_log.txt"

# Смещения в config_4
OFF_VARIANT = 0x00
OFF_SHELL_LEN = 0x04  # 4 байта little-endian unsigned
OFF_DST_LEN = 0x08    # 4 байта little-endian signed/int

# Разделители полей (по ТЗ)
DELIMS = b",:=;"


def ensure_dirs():#создает папки
    OUT_DIR.mkdir(exist_ok=True)
    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    INTERESTING_DIR.mkdir(parents=True, exist_ok=True)
    DRMEM_DIR.mkdir(parents=True, exist_ok=True)

def sha1(data: bytes) -> str:#чтобы не сохранять одинаковые файлы
    return hashlib.sha1(data).hexdigest()

def log(line: str):#
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {line}\n")

def write_u32_le(buf: bytearray, off: int, value: int):#аписываем число в little endian
    buf[off:off + 4] = int(value).to_bytes(4, "little", signed=False)

def write_i32_le(buf: bytearray, off: int, value: int):# со знаком
    buf[off:off + 4] = int(value).to_bytes(4, "little", signed=True)

def find_latest_file(workdir: Path, glob_pat: str) -> Optional[Path]:#функция ищет самый свежий файл
    files = list(workdir.glob(glob_pat))
    if not files:
        return None
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0]

def is_printable_ascii(b: int) -> bool:
    return 0x20 <= b <= 0x7E

def find_latest_drcov_log(workdir: Path) -> Optional[Path]:
    return find_latest_file(workdir, "drcov*.log")

def parse_drcov_log(path: Path) -> Set[Tuple[int, int, int]]:#
    data = path.read_bytes()

    marker = b"BB Table:"
    idx = data.find(marker)
    if idx == -1:
        return set()

    line_end = data.find(b"\n", idx)
    if line_end == -1:
        return set()

    header_line = data[idx:line_end].decode("utf-8", errors="replace")
    parts = header_line.replace(":", " ").split()
    n_bbs = None
    for tok in parts:
        if tok.isdigit():
            n_bbs = int(tok)
            break
    if not n_bbs or n_bbs <= 0:
        return set()

    bb_off = line_end + 1
    entry_size = 8
    need = n_bbs * entry_size
    if bb_off + need > len(data):
        max_n = max(0, (len(data) - bb_off) // entry_size)
        n_bbs = max_n

    cov: Set[Tuple[int, int, int]] = set()
    off = bb_off
    for _ in range(n_bbs):
        if off + 8 > len(data):
            break
        start, size, mod_id = struct.unpack_from("<IHH", data, off)
        cov.add((mod_id, start, size))
        off += 8
    return cov

def run_under_drrun(tool: str,
                    cmd_target: List[str],
                    cwd: Path,
                    timeout_sec: float,
                    extra_tool_args: Optional[List[str]] = None) -> subprocess.CompletedProcess:
    if extra_tool_args is None:
        extra_tool_args = []
    cmd = [str(DRRUN), "-t", tool, *extra_tool_args, "--", *cmd_target]
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_sec
    )

def prepare_input(mut_path: Path, pass_as_arg: bool) -> List[str]:
    if pass_as_arg:
        return [str(TARGET_EXE), str(mut_path)]
    else:
        fixed = TARGET_DIR / TARGET_FIXED_NAME
        shutil.copyfile(mut_path, fixed)
        return [str(TARGET_EXE)]

def classify_returncode(rc: int) -> str:
    # 0xC0000005 access violation, и вообще все 0xC000.... часто exceptions
    if rc == 0:
        return "ok"
    if rc == 0xC0000005 or rc == 3221225477:
        return "crash"
    if rc & 0xC0000000:
        return "crash"
    return "error"

def run_target_drcov(mut_path: Path,
                     pass_as_arg: bool,
                     timeout_sec: float) -> Tuple[str, int, str, Set[Tuple[int, int, int]]]:

    if not DRRUN.exists():
        return ("error", -4, f"drrun.exe not found: {DRRUN}", set())

    # подготовка входа
    try:
        cmd_target = prepare_input(mut_path, pass_as_arg)
    except Exception as e:
        return ("error", -5, f"prepare input failed: {e!r}", set())

    # удалим старые логи
    for old in TARGET_DIR.glob("drcov*.log"):
        try:
            old.unlink()
        except Exception:
            pass

    try:
        p = run_under_drrun("drcov", cmd_target, TARGET_DIR, timeout_sec)
        rc = p.returncode
        details = (p.stderr[:500] or p.stdout[:500]).decode("utf-8", errors="replace")

        log_path = find_latest_drcov_log(TARGET_DIR)
        cov = parse_drcov_log(log_path) if log_path else set()

        status = classify_returncode(rc)
        return (status, rc, details, cov)

    except subprocess.TimeoutExpired:
        return ("timeout", -1, "timeout", set())
    except Exception as e:
        return ("error", -2, repr(e), set())


def collect_drmemory_report(mut_path: Path,
                            pass_as_arg: bool,
                            timeout_sec: float,
                            tag: str) -> Optional[Path]:
    if not DRRUN.exists():
        return None

    DRMEM_DIR.mkdir(parents=True, exist_ok=True)


    try:
        cmd_target = prepare_input(mut_path, pass_as_arg)
    except Exception:
        return None

    logdir = DRMEM_DIR / f"drmem_{tag}"
    if logdir.exists():
        try:
            shutil.rmtree(logdir)
        except Exception:
            pass
    logdir.mkdir(parents=True, exist_ok=True)

    extra_args = ["-logdir", str(logdir), "-quiet", "-batch"]

    try:
        p = run_under_drrun("drmemory", cmd_target, TARGET_DIR, timeout_sec, extra_tool_args=extra_args)
        _ = p  # не критично
    except Exception:
        pass


    rep = find_latest_file(logdir, "*.txt")
    if rep is None:
        rep = find_latest_file(logdir, "*.log")
    return rep


BOUNDARY_BYTES_1 = [0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF]
BOUNDARY_U16 = [0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF]
BOUNDARY_U32 = [0x00000000, 0x00000001, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]

DST_LEN_INTERESTING = [
    0, 1, 16, 128,
    2499, 2500, 2507, 2508, 2509, 2600, 3000, 3058, 4096, 5000, 10000, 65535,
    -1, -256, -2147483648
]
SHELL_LEN_INTERESTING = [407, 4096, 8192, 16384, 32768, 65535, 131072]

def mutate_lengths(seed: bytes) -> Tuple[bytes, str]:

    buf = bytearray(seed)
    buf[OFF_VARIANT] = 0x04
    sh = random.choice(SHELL_LEN_INTERESTING)
    dl = random.choice(DST_LEN_INTERESTING)
    write_u32_le(buf, OFF_SHELL_LEN, sh)
    write_i32_le(buf, OFF_DST_LEN, dl)
    return (bytes(buf), f"patch_lengths shell_len={sh} dst_len={dl}")

def mutate_one_byte(seed: bytes, off: Optional[int] = None) -> Tuple[bytes, str]:
    buf = bytearray(seed)
    if off is None:
        off = random.randrange(0, len(buf))
    old = buf[off]
    # чаще подсовываем boundary
    if random.random() < 0.7:
        buf[off] = random.choice(BOUNDARY_BYTES_1)
    else:
        buf[off] = random.randrange(256)
    return (bytes(buf), f"one_byte off={off:#x} {old:#x}->{buf[off]:#x}")

def mutate_multi_byte(seed: bytes) -> Tuple[bytes, str]:

    buf = bytearray(seed)
    n = random.choice([2, 3, 4, 8, 16])
    off = random.randrange(0, max(1, len(buf) - n))
    old = bytes(buf[off:off+n])

    # Вариант 1: залить 0x00/0xFF
    if random.random() < 0.5:
        fill = random.choice([0x00, 0xFF])
        buf[off:off+n] = bytes([fill]) * n
        return (bytes(buf), f"multi_byte fill={fill:#x} n={n} off={off:#x} old={old.hex()}")
    # Вариант 2: boundary-числа для 2/4 байт
    if n >= 4 and random.random() < 0.7:
        val = random.choice(BOUNDARY_U32)
        buf[off:off+4] = val.to_bytes(4, "little", signed=False)
        return (bytes(buf), f"multi_byte u32={val:#x} off={off:#x} old={old.hex()}")
    if n >= 2:
        val = random.choice(BOUNDARY_U16)
        buf[off:off+2] = val.to_bytes(2, "little", signed=False)
        return (bytes(buf), f"multi_byte u16={val:#x} off={off:#x} old={old.hex()}")

    # fallback random
    for i in range(n):
        buf[off+i] = random.randrange(256)
    return (bytes(buf), f"multi_byte random n={n} off={off:#x} old={old.hex()}")

def mutate_append(seed: bytes) -> Tuple[bytes, str]:

    buf = bytearray(seed)
    n = random.choice([1, 2, 4, 8, 16, 64, 256, 512])
    mode = random.random()
    if mode < 0.33:
        tail = bytes([0x00]) * n
        desc = f"append n={n} byte=0x00"
    elif mode < 0.66:
        tail = bytes([0xFF]) * n
        desc = f"append n={n} byte=0xFF"
    else:
        tail = os.urandom(n)
        desc = f"append n={n} random"
    buf.extend(tail)
    return (bytes(buf), desc)

def find_delimiters_positions(data: bytes) -> List[int]:
    pos = []
    for i, b in enumerate(data):
        if b in DELIMS:
            pos.append(i)
    return pos

def mutate_near_delimiter(seed: bytes) -> Tuple[bytes, str]:

    buf = bytearray(seed)
    pos = find_delimiters_positions(seed)
    if not pos:
        return mutate_one_byte(seed)
    d = random.choice(pos)
    # мутируем в окне [-4; +8] около разделителя
    lo = max(0, d - 4)
    hi = min(len(buf) - 1, d + 8)
    off = random.randrange(lo, hi + 1)
    # не обязательно трогать сам разделитель, но можно
    mutated, desc = mutate_one_byte(bytes(buf), off=off)
    return mutated, f"near_delim delim_off={d:#x} -> {desc}"

def expand_ascii_field(seed: bytes) -> Tuple[bytes, str]:

    data = seed
    spans: List[Tuple[int, int]] = []
    i = 0
    n = len(data)
    while i < n:
        if is_printable_ascii(data[i]) and data[i] not in DELIMS:
            j = i
            while j < n and is_printable_ascii(data[j]) and data[j] not in DELIMS:
                j += 1
            if j - i >= 4:
                spans.append((i, j))
            i = j
        else:
            i += 1

    if not spans:
        # fallback: просто append
        return mutate_append(seed)

    (a, b) = random.choice(spans)
    token = data[a:b]
    grow_by = random.choice([1, 4, 8, 32, 128, 512])
    # вставим в конец токена (между b и b)
    filler = bytes([token[-1]]) * grow_by if token else (b"A" * grow_by)

    out = bytearray(data[:b])
    out.extend(filler)
    out.extend(data[b:])
    return (bytes(out), f"expand_ascii span={a:#x}-{b:#x} grow_by={grow_by} char={filler[:1].hex()}")


def sequential_mutations(seed: bytes):

    for off in range(len(seed)):
        for v in BOUNDARY_BYTES_1:
            buf = bytearray(seed)
            old = buf[off]
            buf[off] = v
            yield bytes(buf), f"sequential off={off:#x} {old:#x}->{v:#x}"

def make_mutation(seed: bytes) -> Tuple[bytes, str]:
    r = random.random()

    if r < 0.45:
        return mutate_lengths(seed)
    if r < 0.60:
        return mutate_near_delimiter(seed)
    if r < 0.75:
        return mutate_multi_byte(seed)
    if r < 0.88:
        return expand_ascii_field(seed)
    if r < 0.97:
        return mutate_append(seed)
    return mutate_one_byte(seed)

def save_case(folder: Path, mutated: bytes, prefix: str, meta: str) -> Path:
    mid = sha1(mutated)[:12]
    path = folder / f"{prefix}_{mid}.bin"
    path.write_bytes(mutated)
    log(f"SAVE {folder.name}/{path.name} meta={meta}")
    return path


def main():
    parser = argparse.ArgumentParser(description="Mutation fuzzer with DynamoRIO drcov feedback")
    parser.add_argument("--iters", type=int, default=MAX_ITERS_DEFAULT)
    parser.add_argument("--timeout", type=float, default=TIMEOUT_SEC_DEFAULT)
    parser.add_argument("--mode", choices=["random", "sequential"], default="random",
                        help="random = разные мутации; sequential = последовательная замена всех байт на boundary")
    parser.add_argument("--pass-as-arg", action="store_true", default=PASS_AS_ARG_DEFAULT,
                        help="если vuln4.exe принимает путь к файлу аргументом")
    args = parser.parse_args()

    ensure_dirs()

    if not SEED_FILE.exists():
        print("SEED_FILE not found:", SEED_FILE)
        return
    if not TARGET_EXE.exists():
        print("TARGET_EXE not found:", TARGET_EXE)
        return
    if not DRRUN.exists():
        print("DRRUN not found:", DRRUN)
        return

    seed = SEED_FILE.read_bytes()
    global_cov: Set[Tuple[int, int, int]] = set()

    # sanity seed
    tmp0 = OUT_DIR / "tmp_seed.bin"
    tmp0.write_bytes(seed)
    st, rc, details, cov = run_target_drcov(tmp0, args.pass_as_arg, args.timeout)
    global_cov |= cov
    log(f"SEED status={st} rc={rc} cov={len(cov)} details={details!r}")
    print(f"[seed] status={st} rc={rc} cov={len(cov)}")



    if args.mode == "sequential":
        seq_iter = sequential_mutations(seed)
        it_source = ((i + 1, m, d) for i, (m, d) in enumerate(seq_iter))
    else:
        def rnd_source():
            for i in range(1, args.iters + 1):
                m, d = make_mutation(seed)
                yield i, m, d
        it_source = rnd_source()

    for it, mutated, mdesc in it_source:
        tmp = OUT_DIR / "tmp.bin"
        tmp.write_bytes(mutated)

        status, rc, details, cov = run_target_drcov(tmp, args.pass_as_arg, args.timeout)

        # crash
        if status == "crash":
            crash_path = save_case(CRASH_DIR, mutated, f"crash_rc{rc}", mdesc + f" details={details!r}")
            print("CRASH SAVED:", crash_path.name, "mut:", mdesc)


            rep = collect_drmemory_report(crash_path, args.pass_as_arg, max(args.timeout, 10.0), tag=crash_path.stem)
            if rep:
                log(f"DRMEM_REPORT {rep}")
                print("DRMEMORY REPORT:", rep)
            else:
                print("DRMEMORY REPORT: not found (ok, but if teacher asks, enable/install drmemory tool)")

            return

        # feedback coverage
        if cov:
            new_cov = cov - global_cov
            if new_cov:
                global_cov |= cov
                p = save_case(INTERESTING_DIR, mutated, f"cov+{len(new_cov)}", mdesc + f" total_cov={len(global_cov)}")
                print(f"[{it}] NEW COVERAGE +{len(new_cov)} total={len(global_cov)} -> {p.name}")

        if status in ("timeout", "error"):
            log(f"{status.upper()} rc={rc} mut={mdesc} details={details!r}")

        if it % 200 == 0:
            print(f"[{it}] ok. total_cov={len(global_cov)}")

        if args.mode == "sequential" and it >= args.iters:
            break

    print("Done, no crash found.")

if __name__ == "__main__":
    main()