"""Generic CSV export helper used by the report generator and GUI pages."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable, Mapping

from utils.logger import get_logger

logger = get_logger(__name__)


def export_rows_to_csv(
    rows: Iterable[Mapping[str, Any]],
    headers: list[str],
    file_path: Path,
) -> Path:
    """
    Write an iterable of dict-like rows to ``file_path`` as CSV using
    ``headers`` as both the column order and the row keys to extract.
    """
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in headers})
    logger.info("Exported %d rows to %s", sum(1 for _ in rows) or 0, file_path)
    return file_path
