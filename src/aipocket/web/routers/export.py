"""Export endpoint — plaintext key download as json/csv."""

from __future__ import annotations

import asyncio
import io

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..auth import get_current_user
from ..exporter import build_export
from ..schemas import ExportRequest

router = APIRouter(prefix="/api/export", tags=["export"], dependencies=[Depends(get_current_user)])


@router.post("")
async def export(body: ExportRequest) -> StreamingResponse:
    # build_export reads run files + serializes — blocking, so run it in a thread.
    content, media_type, filename = await asyncio.to_thread(build_export, body)
    return StreamingResponse(
        io.BytesIO(content),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
