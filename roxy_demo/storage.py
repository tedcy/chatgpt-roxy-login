"""Small atomic JSON store; credentials never appear in list projections."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
from uuid import uuid4

from . import settings
from .primitives import parse_accounts, normalize_proxy

_LOCK_GUARD = threading.Lock()
_LOCKS = {}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class StoreError(RuntimeError):
    pass


class Store:
    def __init__(self, root):
        self.root = Path(root)
        key = os.path.normcase(str(self.root.resolve()))
        with _LOCK_GUARD:
            self.lock = _LOCKS.setdefault(key, threading.RLock())
        # Read before the first write: a damaged file is never reset to empty.
        self._accounts()
        self.get_settings()
        self._migrate_kernel_ids()

    def _migrate_kernel_ids(self):
        with self.lock:
            data = self._accounts()
            if not data["accounts"] or all(type(row.get("kernel_account_id")) is int for row in data["accounts"]):
                return
            path = self.root / "accounts.json"
            backup = self.root / "accounts.pre-upstream.json"
            if path.exists() and not backup.exists():
                with backup.open("xb") as stream:
                    stream.write(path.read_bytes())
                    stream.flush()
                    os.fsync(stream.fileno())
            used = {row["kernel_account_id"] for row in data["accounts"] if type(row.get("kernel_account_id")) is int}
            next_id = max(used, default=0) + 1
            for row in data["accounts"]:
                if type(row.get("kernel_account_id")) is not int:
                    row["kernel_account_id"] = next_id
                    next_id += 1
            self._write("accounts.json", data)

    def _read(self, name, fallback):
        path = self.root / name
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return deepcopy(fallback)
        except (ValueError, OSError, UnicodeError):
            raise StoreError(f"无法读取 {name}，请检查文件；原文件未被覆盖") from None

    def _write(self, name, value):
        path = self.root / name
        temporary = path.with_name(f".{name}.{uuid4().hex}.tmp")
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except (OSError, ValueError, TypeError):
            raise StoreError(f"无法保存 {name}，原文件保持不变") from None
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _accounts(self):
        data = self._read("accounts.json", {"version": 1, "accounts": []})
        if (not isinstance(data, dict) or data.get("version") != 1 or
                not isinstance(data.get("accounts"), list)):
            raise StoreError("accounts.json 结构无效，原文件未被覆盖")
        ids, emails, kernel_ids = set(), set(), set()
        for row in data["accounts"]:
            if (not isinstance(row, dict) or not isinstance(row.get("id"), str) or
                    not isinstance(row.get("email"), str) or row["id"] in ids or row["email"] in emails or
                    not all(isinstance(row.get(key), str) for key in ("password", "totp_secret", "proxy")) or
                    (row.get("session") is not None and not isinstance(row["session"], dict))):
                raise StoreError("accounts.json 账号结构无效，原文件未被覆盖")
            ids.add(row["id"])
            emails.add(row["email"])
            kernel_id = row.get("kernel_account_id")
            if kernel_id is not None:
                if type(kernel_id) is not int or kernel_id <= 0 or kernel_id in kernel_ids:
                    raise StoreError("accounts.json 内核账号 ID 无效或重复，原文件未被覆盖")
                kernel_ids.add(kernel_id)
            session = row.get("session")
            if session is not None and (not isinstance(session.get("info"), dict) or
                                        not isinstance(session.get("cookies"), list) or
                                        not all(isinstance(cookie, dict) for cookie in session["cookies"]) or
                                        not isinstance(session.get("storage", {}), dict)):
                raise StoreError("accounts.json 会话结构无效，原文件未被覆盖")
        return data

    def get_settings(self):
        with self.lock:
            try:
                return settings.validate(settings.upgrade_saved(self._read("settings.json", {})))
            except ValueError as exc:
                raise StoreError(f"settings.json：{exc}") from None

    def save_settings(self, values):
        checked = settings.validate(values)
        with self.lock:
            self._write("settings.json", checked)
        return checked

    def get(self, account_id):
        with self.lock:
            for row in self._accounts()["accounts"]:
                if row["id"] == account_id:
                    return deepcopy(row)
        raise ValueError("账号不存在")

    def list(self):
        with self.lock:
            rows = self._accounts()["accounts"]
        result = []
        for row in rows:
            snapshot = row.get("session") or {}
            info = snapshot.get("info") or {}
            result.append({"id": row["id"], "email": row["email"],
                           "has_proxy": bool(row.get("proxy")),
                           "has_session": bool(snapshot.get("cookies")),
                           "has_token": bool(info.get("accessToken")),
                           "expires": info.get("expires", ""),
                           "saved_at": snapshot.get("saved_at", ""),
                           "last_result": row.get("last_result", "")})
        return result

    def import_accounts(self, text, busy_ids=()):
        records = parse_accounts(text)
        with self.lock:
            data = self._accounts()
            by_email = {row["email"]: row for row in data["accounts"]}
            if any(by_email.get(row["email"], {}).get("id") in busy_ids for row in records):
                raise ValueError("导入包含有窗口或任务的账号，请先关闭；本次未写入")
            added = updated = 0
            next_kernel_id = max((row.get("kernel_account_id", 0) for row in data["accounts"]), default=0) + 1
            for record in records:
                current = by_email.get(record["email"])
                if current is None:
                    current = {"id": uuid4().hex, "kernel_account_id": next_kernel_id, "proxy": "", "session": None}
                    next_kernel_id += 1
                    data["accounts"].append(current)
                    by_email[record["email"]] = current
                    added += 1
                else:
                    updated += 1
                current.update(record, updated_at=now())
            self._write("accounts.json", data)
            return {"added": added, "updated": updated}

    def set_proxy(self, account_id, value):
        normalized = normalize_proxy(value)
        if not normalized:
            raise ValueError("代理不能为空")
        with self.lock:
            data = self._accounts()
            row = next((row for row in data["accounts"] if row["id"] == account_id), None)
            if row is None:
                raise ValueError("账号不存在")
            row.update(proxy=normalized, updated_at=now())
            self._write("accounts.json", data)


    def result(self, account_id, message):
        with self.lock:
            data = self._accounts()
            row = next((row for row in data["accounts"] if row["id"] == account_id), None)
            if row and row.get("last_result") != message:
                row["last_result"] = message
                self._write("accounts.json", data)

    def token(self, account_id):
        row = self.get(account_id)
        return str(((row.get("session") or {}).get("info") or {}).get("accessToken") or "")
