"""
main.py — RootKitChecker Web 后端 (FastAPI)
"""
import asyncio
import json
import os
import shutil
from datetime import datetime
from typing import Optional

from fastapi import (BackgroundTasks, FastAPI, File, Form, HTTPException,
                     UploadFile)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from analyzer import run_analysis
from database import db_conn, init_db

# ── 路径配置 ──────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.environ.get("MEMSCOPE_UPLOADS", os.path.join(BASE_DIR, "uploads"))
RESULTS_DIR = os.environ.get("MEMSCOPE_RESULTS", os.path.join(BASE_DIR, "results"))

os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# ── FastAPI 应用 ──────────────────────────────────────────────────────────
app = FastAPI(title="RootKitChecker Web API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    init_db()


# ── 工具函数 ──────────────────────────────────────────────────────────────
def row_to_dict(row) -> dict:
    return dict(row) if row else {}


# ── API: 镜像列表 ─────────────────────────────────────────────────────────
@app.get("/api/images")
async def list_images():
    """返回所有镜像记录（按创建时间倒序）"""
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM images ORDER BY id DESC"
        ).fetchall()
    return [row_to_dict(r) for r in rows]


# ── API: 镜像详情 ─────────────────────────────────────────────────────────
@app.get("/api/images/{image_id}")
async def get_image(image_id: int):
    """返回单条镜像记录"""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT * FROM images WHERE id=?", (image_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Image not found")
    return row_to_dict(row)


# ── API: 上传镜像并触发分析 ───────────────────────────────────────────────
@app.post("/api/images/upload")
async def upload_image(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    os_type: str = Form("auto"),
):
    """
    上传内存镜像文件，入库后异步触发 RootKitChecker 分析。
    os_type: auto | windows | linux
    """
    # 保存上传文件
    safe_name = os.path.basename(file.filename or "image.raw")
    dest = os.path.join(UPLOADS_DIR, f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{safe_name}")
    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # 入库
    with db_conn() as conn:
        cur = conn.execute(
            """INSERT INTO images (name, path, os_type, status, created_at)
               VALUES (?, ?, ?, 'pending', datetime('now','localtime'))""",
            (safe_name, dest, os_type),
        )
        image_id = cur.lastrowid

    # 异步分析
    background_tasks.add_task(run_analysis, image_id, dest, os_type)

    with db_conn() as conn:
        row = conn.execute("SELECT * FROM images WHERE id=?", (image_id,)).fetchone()
    return row_to_dict(row)


# ── API: 重新分析 ─────────────────────────────────────────────────────────
@app.post("/api/images/{image_id}/reanalyze")
async def reanalyze(image_id: int, background_tasks: BackgroundTasks):
    """重新触发分析（覆盖旧结果）"""
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM images WHERE id=?", (image_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Image not found")
    rec = row_to_dict(row)

    with db_conn() as conn:
        conn.execute(
            "UPDATE images SET status='pending', error_msg=NULL WHERE id=?",
            (image_id,),
        )

    background_tasks.add_task(run_analysis, image_id, rec["path"], rec["os_type"])
    return {"message": "Reanalysis started", "id": image_id}


# ── API: 删除镜像记录 ─────────────────────────────────────────────────────
@app.delete("/api/images/{image_id}")
async def delete_image(image_id: int):
    """删除数据库记录（不删除磁盘文件）"""
    with db_conn() as conn:
        row = conn.execute("SELECT id FROM images WHERE id=?", (image_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Image not found")
        conn.execute("DELETE FROM images WHERE id=?", (image_id,))
    return {"message": "Deleted", "id": image_id}


# ── API: 获取分析结果 JSON ────────────────────────────────────────────────
@app.get("/api/images/{image_id}/result")
async def get_result(image_id: int):
    """返回该镜像的完整分析结果 JSON"""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT status, result_path, error_msg FROM images WHERE id=?",
            (image_id,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Image not found")
    rec = row_to_dict(row)

    if rec["status"] == "error":
        return JSONResponse(
            status_code=200,
            content={"error": rec.get("error_msg", "Unknown error")},
        )
    if rec["status"] != "done" or not rec.get("result_path"):
        return JSONResponse(
            status_code=200,
            content={"status": rec["status"], "message": "Analysis not completed yet"},
        )

    result_path = rec["result_path"]
    if not os.path.exists(result_path):
        raise HTTPException(status_code=404, detail="Result file not found on disk")

    with open(result_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(content=data)


# ── API: 健康检查 ─────────────────────────────────────────────────────────
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}

# ── 静态文件服务（生产模式：前端构建产物）────────────────────────────────
STATIC_DIR = os.path.join(BASE_DIR, "static")
if os.path.isdir(STATIC_DIR):
    from fastapi.responses import FileResponse
    app.mount("/assets", StaticFiles(directory=os.path.join(STATIC_DIR, "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        file_path = os.path.join(STATIC_DIR, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))
