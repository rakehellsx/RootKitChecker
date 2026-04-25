"""
analyzer.py — 异步调用 RootKitChecker 进行内存镜像分析
"""
import asyncio
import json
import os
import subprocess
import sys
from datetime import datetime

from database import db_conn

# ── 路径配置 ──────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
WEB_DIR     = os.path.dirname(BASE_DIR)
PROJ_DIR    = os.path.dirname(WEB_DIR)
MEMSCOPE    = os.environ.get("MEMSCOPE_BIN",    os.path.join(PROJ_DIR, "build", "memscope"))
VENV_DIR    = os.environ.get("MEMSCOPE_VENV",   os.path.join(PROJ_DIR, ".venv"))
RESULTS_DIR = os.environ.get("MEMSCOPE_RESULTS", os.path.join(BASE_DIR, "results"))
SYMBOLS_DIR = os.environ.get("VOLATILITY_SYMBOLS", "")
DUMP_DIR    = os.environ.get("MEMSCOPE_DUMP_DIR", os.path.join(BASE_DIR, "module_dumps"))

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(DUMP_DIR, exist_ok=True)


def _detect_arch(image_path: str) -> str:
    """简单探测镜像架构（读取 ELF/PE 魔数）"""
    try:
        with open(image_path, "rb") as f:
            magic = f.read(8)
        if magic[:4] == b"MZ\x90\x00" or magic[:2] == b"MZ":
            return "x86/x64 (PE)"
        if magic[:4] == b"\x7fELF":
            cls = magic[4]
            return "x86_64" if cls == 2 else "x86"
        return "unknown"
    except Exception:
        return "unknown"


async def run_analysis(image_id: int, image_path: str, os_type: str):
    """
    在后台线程中运行 memscope，完成后将结果写入数据库。
    """
    result_file = os.path.join(RESULTS_DIR, f"result_{image_id}.json")

    # 更新状态为 running
    with db_conn() as conn:
        conn.execute(
            "UPDATE images SET status='running' WHERE id=?", (image_id,)
        )

    # 探测架构
    arch = _detect_arch(image_path)
    with db_conn() as conn:
        conn.execute("UPDATE images SET arch=? WHERE id=?", (arch, image_id))

    # 构建命令
    cmd = [MEMSCOPE, "-i", image_path, "-o", result_file, "--pretty"]
    if os_type and os_type != "auto":
        cmd += ["--os", os_type]
    if SYMBOLS_DIR:
        cmd += ["--symbols", SYMBOLS_DIR]
    cmd += ["--dump-dir", DUMP_DIR]

    env = os.environ.copy()
    env["MEMSCOPE_VENV"] = VENV_DIR

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
        rc = proc.returncode

        if rc == 0 and os.path.exists(result_file):
            # 从 JSON 结果中提取 os_type（若为 auto 则更新）
            detected_os = os_type
            try:
                with open(result_file, "r") as f:
                    data = json.load(f)
                detected_os = data.get("os_type", os_type) or os_type
            except Exception:
                pass

            with db_conn() as conn:
                conn.execute(
                    """UPDATE images
                       SET status='done', finished_at=?, result_path=?, os_type=?
                       WHERE id=?""",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     result_file, detected_os, image_id),
                )
        else:
            err = stderr.decode(errors="replace")[-2000:]
            with db_conn() as conn:
                conn.execute(
                    """UPDATE images
                       SET status='error', finished_at=?, error_msg=?
                       WHERE id=?""",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), err, image_id),
                )
    except asyncio.TimeoutError:
        with db_conn() as conn:
            conn.execute(
                """UPDATE images SET status='error', finished_at=?, error_msg=?
                   WHERE id=?""",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                 "Analysis timed out (>1h)", image_id),
            )
    except Exception as exc:
        with db_conn() as conn:
            conn.execute(
                """UPDATE images SET status='error', finished_at=?, error_msg=?
                   WHERE id=?""",
                (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), str(exc), image_id),
            )
