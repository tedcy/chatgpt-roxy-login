"""Account import and proxy input adapters; browser/auth logic is in upstream/."""
import base64
import re
import unicodedata
from urllib.parse import quote, unquote, urlsplit, urlunsplit, urlparse

PROXY_INVALID = "代理格式无效，请填写供应商格式或 HTTP/HTTPS/SOCKS5 代理 URL"

_SCHEMES = {"http", "https", "socks5", "socks5h"}

def parse_accounts(text):
    if not isinstance(text, str) or len(text) > 2 * 1024 * 1024:
        raise ValueError("导入文本无效或超过 2 MB")
    records = {}
    for number, line in enumerate(text.lstrip("\ufeff").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        separator = next((value for value in ("----", "====", "--") if value in line), None)
        parts = line.split(separator) if separator else []
        if len(parts) != 3:
            raise ValueError(f"第 {number} 行需要邮箱、密码、2FA 三段")
        email, password, secret = (part.strip() for part in parts)
        if not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", email) or len(email) > 320 or not password:
            raise ValueError(f"第 {number} 行邮箱或密码无效")
        try:
            secret = normalise_totp_secret(secret)
        except ValueError:
            raise ValueError(f"第 {number} 行 2FA 密钥不是有效 Base32") from None
        email = email.lower()
        records[email] = dict(email=email, password=password, totp_secret=secret)
    if not records:
        raise ValueError("没有可导入的账号")
    return list(records.values())

class LoginPrimitiveError(ValueError):
    pass

class TotpSecretError(LoginPrimitiveError):
    pass

def normalize_proxy(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(PROXY_INVALID)
    raw = value.strip()
    if not raw:
        return ""
    try:
        if len(raw) > 4096 or any(ord(char) < 32 or ord(char) == 127 for char in raw):
            raise ValueError()
        if "://" not in raw:
            parts = raw.split(":", 3)
            if len(parts) != 4 or not all(parts):
                raise ValueError()
            host, port, username, password = parts
            if not port.isascii() or not port.isdigit() or any(char in host for char in "/?#@\\"):
                raise ValueError()
            raw = f"http://{quote(username, safe='')}:{quote(password, safe='')}@{host}:{port}"
        parsed = urlsplit(raw)
        host, port = parsed.hostname, parsed.port
        if (parsed.scheme not in _SCHEMES or not host or port is None or not 1 <= port <= 65535
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                or any(char.isspace() or char in "/?#@\\%" for char in host)):
            raise ValueError()
        authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        if parsed.username is not None:
            username = quote(unquote(parsed.username, errors="strict"), safe="")
            password = (
                ":" + quote(unquote(parsed.password, errors="strict"), safe="")
                if parsed.password is not None else ""
            )
            authority = f"{username}{password}@{authority}"
        return urlunsplit((parsed.scheme, authority, "", "", ""))
    except (ValueError, UnicodeError):
        raise ValueError(PROXY_INVALID) from None

def normalise_totp_secret(value: object) -> str:
    """Validate and normalize the committed Base32 TOTP secret."""
    secret = re.sub(r"\s+", "", str(value or "")).upper()
    if not secret:
        raise TotpSecretError("session_login_totp_secret_missing")
    if not re.fullmatch(r"[A-Z2-7]+=*", secret):
        raise TotpSecretError("session_login_totp_secret_invalid")
    padding = "=" * ((8 - len(secret) % 8) % 8)
    try:
        decoded = base64.b32decode(secret + padding, casefold=True)
        if not decoded:
            raise ValueError("empty")
    except Exception as exc:
        raise TotpSecretError("session_login_totp_secret_invalid") from exc
    return secret
