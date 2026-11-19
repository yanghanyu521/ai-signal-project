"""Script-only analysis scope.

Binary artifacts (PE/ELF/APK/DEX/archives/packed blobs) are out of scope for
feature extraction. Detection is extension-first with a content fallback so
extensionless scripts (e.g. the FruitShell sample) are still accepted.
"""
from __future__ import annotations

from pathlib import Path

SCRIPT_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".sh": "shell",
    ".bash": "shell",
    ".bat": "batch",
    ".cmd": "batch",
    ".php": "php",
    ".pl": "perl",
    ".rb": "ruby",
    ".lua": "lua",
}

SCRIPT_SHEBANGS = {
    "python": "python",
    "node": "javascript",
    "nodejs": "javascript",
    "perl": "perl",
    "ruby": "ruby",
    "php": "php",
    "bash": "shell",
    "sh": "shell",
}

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi", ".so", ".dylib", ".o",
    ".bin", ".dat", ".apk", ".dex", ".jar", ".class", ".zip", ".rar", ".7z",
    ".gz", ".xz", ".zst", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".png",
    ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".pif",
}

_TEXT_KEYWORDS = (
    "import ", "from ", "require(", "function ", "def ", "sub ", "dim ",
    "set ", "echo ", "print", "wscript", "invoke-", "param(", "const ",
    "var ", "let ", "option explicit", "#include", "package ",
)


def _looks_like_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:65536]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            sample.decode("utf-16")
            return True
        except UnicodeDecodeError:
            return False


def detect_script(path: Path, *, read_bytes: int = 65536) -> tuple[bool, str | None, str | None]:
    """Return (is_script, language, rejection_reason)."""
    suffix = path.suffix.lower()
    with path.open("rb") as handle:
        head = handle.read(read_bytes)
    if suffix in BINARY_EXTENSIONS:
        return False, None, f"二进制/文档/打包文件不在分析范围内（{suffix}）"
    if head.startswith(b"MZ") or head.startswith(b"\x7fELF") or head.startswith(b"dex\n"):
        return False, None, "可执行二进制不在分析范围内"
    if suffix in SCRIPT_EXTENSIONS:
        return True, SCRIPT_EXTENSIONS[suffix], None
    if _looks_like_text(head):
        text = head.decode("utf-8", errors="replace").lstrip()
        if text.startswith("#!"):
            first_line = text.split("\n", 1)[0].lower()
            for marker, language in SCRIPT_SHEBANGS.items():
                if marker in first_line:
                    return True, language, None
        lowered = text[:8192].lower()
        if any(keyword in lowered for keyword in _TEXT_KEYWORDS):
            language = "powershell" if "invoke-" in lowered or "param(" in lowered else None
            return True, language, None
        return True, None, None
    return False, None, "内容不是可识别的脚本源码（非文本或不含脚本结构）"
