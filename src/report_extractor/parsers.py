from __future__ import annotations

import mimetypes
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from bs4 import BeautifulSoup

from .utils import normalize_space, sha256_text, stable_id


def _block(document_id: str, index: int, text: str, *, kind: str, section: str | None = None, page: int | None = None) -> dict:
    clean = normalize_space(text)
    return {
        "block_id": stable_id("block", document_id, index, clean),
        "index": index,
        "kind": kind,
        "section": section,
        "page": page,
        "paragraph": index + 1,
        "char_start": 0,
        "char_end": len(clean),
        "text": clean,
        "text_sha256": sha256_text(clean),
    }


def parse_html(path: str | Path, document_id: str) -> dict:
    raw = Path(path).read_bytes()
    soup = BeautifulSoup(raw, "lxml")
    for tag in soup(["script", "style", "noscript", "svg", "form", "nav", "footer"]):
        tag.decompose()
    title = normalize_space(soup.title.get_text(" ") if soup.title else "") or None
    html_language = normalize_space((soup.html or {}).get("lang") if soup.html else "") or None
    authors = []
    for selector in [
        ("meta", {"name": "author"}, "content"),
        ("meta", {"property": "article:author"}, "content"),
    ]:
        tag = soup.find(selector[0], attrs=selector[1])
        value = normalize_space(tag.get(selector[2]) if tag else "")
        if value and value not in authors:
            authors.append(value)
    publication_date = None
    for attrs in [
        {"property": "article:published_time"}, {"name": "date"},
        {"name": "datePublished"}, {"itemprop": "datePublished"},
    ]:
        tag = soup.find("meta", attrs=attrs)
        value = normalize_space(tag.get("content") if tag else "")
        if value:
            publication_date = value
            break
    if not publication_date:
        time_tag = soup.find("time", attrs={"datetime": True})
        publication_date = normalize_space(time_tag.get("datetime") if time_tag else "") or None
    blocks: list[dict] = []
    section = None
    for element in soup.find_all(["h1", "h2", "h3", "h4", "p", "li", "table", "figcaption"]):
        text = normalize_space(element.get_text(" ", strip=True))
        if not text or len(text) < 2:
            continue
        kind = element.name
        if kind in {"h1", "h2", "h3", "h4"}:
            section = text
            kind = "heading"
        elif kind == "table":
            kind = "table"
        elif kind == "figcaption":
            kind = "caption"
        else:
            kind = "paragraph"
        if blocks and blocks[-1]["text"] == text:
            continue
        blocks.append(_block(document_id, len(blocks), text, kind=kind, section=section))
    return {"title": title, "authors": authors, "publication_date": publication_date, "language": html_language, "content_type": "html", "blocks": blocks}


def parse_pdf(path: str | Path, document_id: str) -> dict:
    try:
        import pdfplumber
    except ImportError as exc:
        raise RuntimeError("PDF 解析需要 pdfplumber") from exc
    blocks: list[dict] = []
    title = None
    with pdfplumber.open(path) as pdf:
        metadata = pdf.metadata or {}
        title = normalize_space(str(metadata.get("Title") or "")) or None
        for page_number, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            for paragraph in [part for part in text.splitlines() if normalize_space(part)]:
                blocks.append(_block(document_id, len(blocks), paragraph, kind="paragraph", page=page_number))
            for table_number, table in enumerate(page.extract_tables() or [], start=1):
                rows = [" | ".join(normalize_space(cell) for cell in row if cell is not None) for row in table]
                table_text = "\n".join(row for row in rows if row)
                if table_text:
                    item = _block(document_id, len(blocks), table_text, kind="table", page=page_number)
                    item["table"] = f"page-{page_number}-table-{table_number}"
                    blocks.append(item)
    author = normalize_space(str(metadata.get("Author") or ""))
    publication_date = normalize_space(str(metadata.get("CreationDate") or "")) or None
    return {"title": title, "authors": [author] if author else [], "publication_date": publication_date, "language": None, "content_type": "pdf", "blocks": blocks}


def parse_text(path: str | Path, document_id: str) -> dict:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    blocks = [
        _block(document_id, index, part, kind="paragraph")
        for index, part in enumerate(part for part in text.splitlines() if normalize_space(part))
    ]
    return {"title": None, "authors": [], "publication_date": None, "language": None, "content_type": "text", "blocks": blocks}


def parse_docx(path: str | Path, document_id: str) -> dict:
    """Parse text-bearing DOCX paragraphs and tables without executing document content."""
    word_ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    core_ns = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
    dc_ns = "http://purl.org/dc/elements/1.1/"
    dcterms_ns = "http://purl.org/dc/terms/"

    def text_of(element: ET.Element) -> str:
        return normalize_space(" ".join(node.text or "" for node in element.iter(f"{{{word_ns}}}t")))

    title = None
    authors: list[str] = []
    publication_date = None
    with zipfile.ZipFile(path) as archive:
        try:
            document_root = ET.fromstring(archive.read("word/document.xml"))
        except KeyError as exc:
            raise ValueError("DOCX缺少word/document.xml") from exc
        if "docProps/core.xml" in archive.namelist():
            core = ET.fromstring(archive.read("docProps/core.xml"))
            title_node = core.find(f"{{{dc_ns}}}title")
            creator_node = core.find(f"{{{dc_ns}}}creator")
            created_node = core.find(f"{{{dcterms_ns}}}created")
            title = normalize_space(title_node.text if title_node is not None else "") or None
            creator = normalize_space(creator_node.text if creator_node is not None else "")
            if creator:
                authors.append(creator)
            publication_date = normalize_space(created_node.text if created_node is not None else "") or None

    body = document_root.find(f"{{{word_ns}}}body")
    blocks: list[dict] = []
    section = None
    if body is not None:
        for element in body:
            if element.tag == f"{{{word_ns}}}p":
                text = text_of(element)
                if not text:
                    continue
                style_node = element.find(f"./{{{word_ns}}}pPr/{{{word_ns}}}pStyle")
                style = style_node.get(f"{{{word_ns}}}val", "") if style_node is not None else ""
                is_heading = style.lower().startswith("heading") or style.lower() == "title"
                if is_heading:
                    section = text
                blocks.append(_block(document_id, len(blocks), text, kind="heading" if is_heading else "paragraph", section=section))
            elif element.tag == f"{{{word_ns}}}tbl":
                rows = []
                for row in element.findall(f"{{{word_ns}}}tr"):
                    cells = [text_of(cell) for cell in row.findall(f"{{{word_ns}}}tc")]
                    row_text = " | ".join(cell for cell in cells if cell)
                    if row_text:
                        rows.append(row_text)
                if rows:
                    blocks.append(_block(document_id, len(blocks), "\n".join(rows), kind="table", section=section))
    return {"title": title, "authors": authors, "publication_date": publication_date, "language": None, "content_type": "docx", "blocks": blocks}


def parse_document(path: str | Path, document_id: str, content_type: str | None = None) -> dict:
    source = Path(path)
    guessed = content_type or mimetypes.guess_type(source.name)[0] or ""
    if guessed in {"text/html", "application/xhtml+xml"} or source.suffix.lower() in {".html", ".htm"}:
        return parse_html(source, document_id)
    if guessed == "application/pdf" or source.suffix.lower() == ".pdf":
        return parse_pdf(source, document_id)
    if guessed == "application/vnd.openxmlformats-officedocument.wordprocessingml.document" or source.suffix.lower() == ".docx":
        return parse_docx(source, document_id)
    if guessed == "text/plain" or source.suffix.lower() in {".txt", ".md"}:
        return parse_text(source, document_id)
    raise ValueError(f"不支持的文档类型: {guessed or source.suffix}")
