"""
Standardized API response format for NanoVault v1.0.1.

All endpoints return:
  Success: {"success": true,  "message": "...", "data": {...}}
  Failure: {"success": false, "error": "...",   "details": {...}}
"""
from typing import Any, Optional
from fastapi import HTTPException
from fastapi.responses import JSONResponse


def ok(data: Any = None, message: str = "OK", status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"success": True, "message": message, "data": data},
    )


def created(data: Any = None, message: str = "Created") -> JSONResponse:
    return JSONResponse(
        status_code=201,
        content={"success": True, "message": message, "data": data},
    )


def error(message: str, details: Any = None, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "error": message, "details": details or {}},
    )


def paginated(
    items: list,
    total: int,
    page: int,
    page_size: int,
    message: str = "OK",
) -> JSONResponse:
    import math
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": message,
            "data": {
                "items": items,
                "pagination": {
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "pages": math.ceil(total / page_size) if total else 0,
                },
            },
        },
    )
