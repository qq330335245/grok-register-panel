"""Cloudflare Temp Mail admin mode (codex-console compatible).

Separate from the anonymous ``cloudflare`` provider (``/api/new_address``).
Uses admin password via ``x-admin-auth`` and creates addresses with
``POST /admin/new_address``. Mail reading prefers the address JWT, then falls
back to ``/admin/mails``.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.policy import default as email_policy
from email.header import decode_header, make_header
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from email_providers.common import extract_verification_code, generate_username, pick_list_payload

HttpGet = Callable[..., Any]
HttpPost = Callable[..., Any]

MAIL_LIST_LIMIT = 5
FORWARD_MAIL_LIST_LIMIT = 40
DEFAULT_POLL_INTERVAL = 8.0
MAX_POLL_INTERVAL = 12.0
ADMIN_MAIL_LIMITS: Tuple[int, ...] = (5, 1)


def mail_has_body(mail: dict) -> bool:
    if not isinstance(mail, dict):
        return False
    for field in ("raw", "text", "content", "body", "snippet", "intro"):
        if str(mail.get(field) or "").strip():
            return True
    html = mail.get("html")
    if isinstance(html, str) and html.strip():
        return True
    if isinstance(html, list) and any(str(item or "").strip() for item in html):
        return True
    return False


def next_poll_sleep(poll_interval: float, round_index: int = 0) -> float:
    base = max(float(poll_interval or DEFAULT_POLL_INTERVAL), 1.0)
    try:
        step = max(0, int(round_index))
    except Exception:
        step = 0
    return min(MAX_POLL_INTERVAL, base * (1.35 ** step))




def parse_domains(raw: str) -> List[str]:
    """Parse one or more domains separated by comma/semicolon/whitespace/newlines."""
    text = str(raw or "").strip()
    if not text:
        return []
    parts = re.split(r"[,;\s]+", text)
    domains: List[str] = []
    seen = set()
    for part in parts:
        domain = str(part or "").strip().lstrip("@").lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
    return domains


def normalize_path(path: str, default: str) -> str:
    raw = str(path or default or "").strip() or default
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def admin_headers(
    admin_password: str,
    *,
    custom_auth: str = "",
    content_type: bool = False,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    headers: Dict[str, str] = {"Accept": "application/json"}
    if content_type:
        headers["Content-Type"] = "application/json"
    password = str(admin_password or "").strip()
    if password:
        headers["x-admin-auth"] = password
    custom = str(custom_auth or "").strip()
    if custom:
        headers["x-custom-auth"] = custom
    if extra:
        for key, value in extra.items():
            if value is not None and str(value) != "":
                headers[key] = str(value)
    return headers


def user_headers(
    jwt: str,
    *,
    custom_auth: str = "",
    mode: str = "bearer",
) -> Dict[str, str]:
    headers: Dict[str, str] = {"Accept": "application/json"}
    token = str(jwt or "").strip()
    if token:
        if mode == "x-user-token":
            headers["x-user-token"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
    custom = str(custom_auth or "").strip()
    if custom:
        headers["x-custom-auth"] = custom
    return headers


def _response_error_detail(resp: Any) -> str:
    try:
        data = resp.json()
        return str(data)[:400]
    except Exception:
        text = getattr(resp, "text", "") or ""
        return str(text)[:400]


def create_address(
    http_post: HttpPost,
    api_base: str,
    *,
    admin_password: str,
    domain: str,
    custom_auth: str = "",
    create_path: str = "/admin/new_address",
    enable_prefix: bool = True,
    name: str = "",
) -> Tuple[str, str]:
    """Create mailbox via admin API. Returns (address, jwt)."""
    base = str(api_base or "").rstrip("/")
    if not base:
        raise Exception("cf_admin API Base 未配置")
    password = str(admin_password or "").strip()
    if not password:
        raise Exception("cf_admin 管理员密码未配置 (x-admin-auth)")
    domains = parse_domains(domain)
    domain_clean = domains[0] if domains else ""
    if not domain_clean:
        raise Exception("cf_admin 域名未配置")

    path = normalize_path(create_path, "/admin/new_address")
    url = f"{base}{path}"
    local_name = str(name or "").strip() or generate_username(10)
    payload = {
        "enablePrefix": bool(enable_prefix),
        "name": local_name,
        "domain": domain_clean,
    }
    headers = admin_headers(password, custom_auth=custom_auth, content_type=True)
    resp = http_post(url, json=payload, headers=headers)
    if getattr(resp, "status_code", 0) >= 400:
        raise Exception(
            f"cf_admin 创建邮箱 HTTP {resp.status_code}: {_response_error_detail(resp)}"
        )
    try:
        data = resp.json()
    except Exception:
        raise Exception(f"cf_admin 创建邮箱返回非 JSON: {_response_error_detail(resp)}")
    if not isinstance(data, dict):
        raise Exception(f"cf_admin 创建邮箱返回格式错误: {data}")
    address = str(data.get("address") or "").strip()
    jwt = str(data.get("jwt") or "").strip()
    if not address:
        raise Exception(f"cf_admin 创建邮箱缺少 address: {data}")
    # Some deployments may omit jwt; admin mail fallback still works.
    return address, jwt


def _extract_mails(payload: Any) -> List[dict]:
    items = pick_list_payload(payload)
    if items:
        return items
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("mails", "items", "list"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def list_user_mails(
    http_get: HttpGet,
    api_base: str,
    jwt: str,
    *,
    messages_path: str = "/api/mails",
    custom_auth: str = "",
    limit: int = MAIL_LIST_LIMIT,
    offset: int = 0,
) -> List[dict]:
    base = str(api_base or "").rstrip("/")
    token = str(jwt or "").strip()
    if not base or not token:
        return []
    path = normalize_path(messages_path, "/api/mails")
    mode = "x-user-token" if path.rstrip("/").lower() == "/user_api/mails" else "bearer"
    headers = user_headers(token, custom_auth=custom_auth, mode=mode)
    url = f"{base}{path}"
    resp = http_get(
        url,
        headers=headers,
        params={"limit": max(1, int(limit)), "offset": max(0, int(offset))},
    )
    if getattr(resp, "status_code", 0) >= 400:
        raise Exception(
            f"cf_admin 用户邮件接口失败: {path} HTTP {resp.status_code}"
        )
    return _extract_mails(resp.json())


def list_admin_mails(
    http_get: HttpGet,
    api_base: str,
    *,
    admin_password: str,
    custom_auth: str = "",
    admin_mails_path: str = "/admin/mails",
    address: str = "",
    preferred_limit: int = MAIL_LIST_LIMIT,
    offset: int = 0,
) -> List[dict]:
    base = str(api_base or "").rstrip("/")
    password = str(admin_password or "").strip()
    if not base or not password:
        return []
    path = normalize_path(admin_mails_path, "/admin/mails")
    url = f"{base}{path}"
    headers = admin_headers(password, custom_auth=custom_auth)
    limits: List[int] = []
    for value in (preferred_limit, *ADMIN_MAIL_LIMITS):
        try:
            number = max(1, int(value))
        except Exception:
            continue
        if number not in limits:
            limits.append(number)

    last_error = ""
    for limit in limits:
        params: Dict[str, Any] = {"limit": limit, "offset": max(0, int(offset))}
        if address:
            params["address"] = address
        try:
            resp = http_get(url, headers=headers, params=params)
            status = getattr(resp, "status_code", 0)
            if status >= 400:
                detail = _response_error_detail(resp)
                last_error = f"HTTP {status}: {detail}"
                # Invalid limit -> try smaller
                if "limit" in detail.lower() or status == 400:
                    continue
                raise Exception(f"cf_admin admin mails {last_error}")
            return _extract_mails(resp.json())
        except Exception as exc:
            last_error = str(exc)
            if "limit" in last_error.lower():
                continue
            raise
    if last_error:
        raise Exception(f"cf_admin admin mails 失败: {last_error}")
    return []


def check_health(
    http_get: HttpGet,
    api_base: str,
    *,
    admin_password: str,
    custom_auth: str = "",
    admin_mails_path: str = "/admin/mails",
) -> Tuple[bool, str]:
    base = str(api_base or "").rstrip("/")
    password = str(admin_password or "").strip()
    if not base:
        return False, "未配置 cf_admin_api_base"
    if not password:
        return False, "未配置 cf_admin_password"
    try:
        list_admin_mails(
            http_get,
            base,
            admin_password=password,
            custom_auth=custom_auth,
            admin_mails_path=admin_mails_path,
            preferred_limit=1,
            offset=1,
        )
        return True, f"admin mails OK ({base})"
    except Exception as exc:
        return False, str(exc)


def wait_for_code(
    http_get: HttpGet,
    api_base: str,
    *,
    email: str,
    jwt: str = "",
    admin_password: str = "",
    custom_auth: str = "",
    messages_path: str = "/api/mails",
    admin_mails_path: str = "/admin/mails",
    timeout: float = 180,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    log_callback: Optional[Callable[[str], None]] = None,
    cancel_callback: Optional[Callable[[], bool]] = None,
    resend_callback: Optional[Callable[[], None]] = None,
    raise_if_cancelled: Optional[Callable[[Optional[Callable[[], bool]]], None]] = None,
    sleep_with_cancel: Optional[Callable[[float, Optional[Callable[[], bool]]], None]] = None,
) -> str:
    deadline = time.time() + max(float(timeout), 1.0)
    seen_attempts: Dict[str, int] = {}
    next_resend_at = time.time() + 35
    target = str(email or "").strip()
    round_index = 0

    def _raise_if_cancelled() -> None:
        if raise_if_cancelled is not None:
            raise_if_cancelled(cancel_callback)
            return
        if cancel_callback and cancel_callback():
            raise Exception("用户停止注册")

    def _sleep(seconds: float) -> None:
        if sleep_with_cancel is not None:
            sleep_with_cancel(seconds, cancel_callback)
            return
        end = time.time() + max(seconds, 0)
        while time.time() < end:
            _raise_if_cancelled()
            time.sleep(min(0.2, end - time.time()))

    while time.time() < deadline:
        _raise_if_cancelled()
        if resend_callback and time.time() >= next_resend_at:
            try:
                resend_callback()
                if log_callback:
                    log_callback("[*] 已触发重新发送验证码")
            except Exception as exc:
                if log_callback:
                    log_callback(f"[Debug] 触发重发验证码失败: {exc}")
            next_resend_at = time.time() + 35
        try:
            messages = list_messages(
                http_get,
                api_base,
                jwt=jwt,
                admin_password=admin_password,
                custom_auth=custom_auth,
                target_email=target,
                messages_path=messages_path,
                admin_mails_path=admin_mails_path,
            )
        except Exception as exc:
            if log_callback:
                log_callback(f"[Debug] cf_admin 拉取邮件失败: {exc}")
            _sleep(next_poll_sleep(poll_interval, round_index))
            round_index += 1
            continue
        if log_callback:
            log_callback(f"[Debug] cf_admin 本轮邮件数量: {len(messages)}")
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            msg_id = str(
                msg.get("id")
                or msg.get("mail_id")
                or msg.get("mailId")
                or msg.get("msgid")
                or msg.get("_id")
                or ""
            ).strip()
            key = msg_id or str(id(msg))
            attempt = int(seen_attempts.get(key, 0))
            if attempt >= 5:
                continue
            seen_attempts[key] = attempt + 1
            addr = str(msg.get("address") or "").lower()
            if target and addr != target.lower() and not mail_matches_address(msg, target):
                if log_callback:
                    log_callback(
                        f"[Debug] cf_admin 跳过非目标邮件 id={msg_id} target={target}"
                    )
                continue
            combined, subject = combine_mail_text(msg)
            if msg_id and not mail_has_body(msg):
                detail = get_mail_detail(
                    http_get,
                    api_base,
                    msg_id,
                    jwt=jwt,
                    admin_password=admin_password,
                    custom_auth=custom_auth,
                    messages_path=messages_path,
                    admin_mails_path=admin_mails_path,
                )
                if detail:
                    extra, detail_subject = combine_mail_text(detail)
                    if extra:
                        combined = (combined + "\n" + extra).strip()
                    if not subject and detail_subject:
                        subject = detail_subject
            if log_callback:
                log_callback(f"[Debug] cf_admin 收到邮件: {subject}")
            code = extract_verification_code(combined, subject)
            if code:
                if log_callback:
                    log_callback(f"[*] cf_admin 从邮件中提取到验证码: {code}")
                return code
            if log_callback:
                log_callback(
                    f"[Debug] cf_admin 邮件未提取到验证码 id={msg_id} attempt={attempt + 1}"
                )
        _sleep(next_poll_sleep(poll_interval, round_index))
        round_index += 1
    raise Exception(f"cf_admin 在 {int(timeout)}s 内未收到验证码邮件")

def _decode_mime_header(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    try:
        return str(make_header(decode_header(text)))
    except Exception:
        return text


def extract_x_icloud_hme_alias(mail: dict) -> str:
    """Extract HME alias from Apple's X-ICLOUD-HME header in raw.

    Real raw example:
      X-ICLOUD-HME: p=alias@icloud.com; d=; f=forward@example.com; r=to; s=noreply@x.ai

    `p=` is the Hide My Email alias. This is the authoritative key for this inbox.
    """
    if not isinstance(mail, dict):
        return ""
    blobs: List[str] = []
    for key in ("raw", "text", "content", "body", "headers", "header"):
        val = mail.get(key)
        if isinstance(val, str) and val.strip():
            blobs.append(val)
        elif isinstance(val, dict):
            # headers map
            for hk, hv in val.items():
                if str(hk).lower().replace("_", "-") in ("x-icloud-hme", "x-icloud-hme".lower()):
                    blobs.append(f"{hk}: {hv}")
                else:
                    blobs.append(str(hv or ""))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    blobs.append(item)
                elif isinstance(item, dict):
                    name = str(item.get("name") or item.get("key") or "")
                    value = str(item.get("value") or item.get("content") or "")
                    if name:
                        blobs.append(f"{name}: {value}")
                    elif value:
                        blobs.append(value)

    blob = "\n".join(blobs)
    if not blob:
        return ""

    # Primary: X-ICLOUD-HME: p=alias@domain
    m = re.search(
        r"(?im)^x-icloud-hme\s*:\s*.*?\bp=([^;\s]+)",
        blob,
    )
    if m:
        return str(m.group(1) or "").strip().lower()

    # Same header may appear without line-start after folding
    m = re.search(r"(?i)x-icloud-hme\s*:\s*.*?\bp=([^\s;]+)", blob)
    if m:
        return str(m.group(1) or "").strip().lower()

    # Fallback visible in same raw: To: Hide My Email <alias@icloud.com>
    m = re.search(
        r"(?im)^to\s*:\s*(?:hide my email\s*)?<?([a-z0-9._%+\-]+@icloud\.com)>?",
        blob,
    )
    if m:
        return str(m.group(1) or "").strip().lower()

    return ""


def mail_targets_hme_alias(mail: dict, alias_email: str) -> bool:
    """True only if this mail's X-ICLOUD-HME p= (or To HME) equals the alias."""
    alias = str(alias_email or "").strip().lower()
    if not alias or not isinstance(mail, dict):
        return False
    found = extract_x_icloud_hme_alias(mail)
    if found and found == alias:
        return True
    # last fallback: exact alias token in raw only (not forward mailbox alone)
    raw = str(mail.get("raw") or "")
    if not raw:
        return False
    return bool(
        re.search(
            r"(?<![a-z0-9._%+\-])" + re.escape(alias) + r"(?![a-z0-9._%+\-])",
            raw,
            re.I,
        )
    )


# Back-compat aliases used by older call sites
def mail_appears_for_email(mail: dict, email: str) -> bool:
    return mail_targets_hme_alias(mail, email)


def mail_matches_address(mail: dict, target_email: str) -> bool:
    return mail_targets_hme_alias(mail, target_email)


def extract_recipient_candidates(mail: dict) -> List[str]:
    alias = extract_x_icloud_hme_alias(mail)
    return [alias] if alias else []


def extract_hme_from_key(mail: dict) -> str:
    # deprecated; keep stub so old imports don't crash
    return ""


def mail_timestamp(mail: dict) -> float:
    if not isinstance(mail, dict):
        return 0.0
    from datetime import datetime, timezone
    for key in (
        "created_at",
        "createdAt",
        "timestamp",
        "time",
        "date",
        "received_at",
        "receivedAt",
    ):
        val = mail.get(key)
        if val is None or val == "":
            continue
        try:
            if isinstance(val, (int, float)):
                num = float(val)
                return num / 1000.0 if num > 1e12 else num
            text = str(val).strip()
            if text.isdigit():
                num = float(text)
                return num / 1000.0 if num > 1e12 else num
            text19 = text[:19].replace("T", " ")
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M"):
                try:
                    dt = datetime.strptime(text19, fmt)
                    return dt.replace(tzinfo=timezone.utc).timestamp()
                except Exception:
                    pass
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            except Exception:
                pass
        except Exception:
            continue
    return 0.0


def mail_message_id(mail: dict) -> str:
    if not isinstance(mail, dict):
        return ""
    for key in ("id", "mail_id", "mailId", "message_id", "messageId", "_id"):
        val = mail.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    subj = str(mail.get("subject") or mail.get("title") or "")
    created = str(mail.get("created_at") or mail.get("createdAt") or mail.get("timestamp") or "")
    return f"{subj}|{created}"


def is_xai_confirmation_mail(mail: dict) -> bool:
    if not isinstance(mail, dict):
        return False
    combined, subject = combine_mail_text(mail)
    blob = f"{subject}\n{combined}".lower()
    if "spacexai" in blob or "x.ai" in blob:
        if (
            "confirmation code" in blob
            or "verification code" in blob
            or "validate your email" in blob
        ):
            return True
    if "confirmation code" in str(subject or "").lower() and "-" in str(subject or ""):
        return True
    return False


def list_forward_mailbox_mails(
    http_get: HttpGet,
    api_base: str,
    *,
    forward_email: str,
    admin_password: str = "",
    custom_auth: str = "",
    admin_mails_path: str = "/admin/mails",
    preferred_limit: int = FORWARD_MAIL_LIST_LIMIT,
) -> List[dict]:
    forward = str(forward_email or "").strip().lower()
    if not forward or not admin_password:
        return []
    # Let callers observe real fetch errors (proxy/auth/network) instead of silent empty.
    mails = list_admin_mails(
        http_get,
        api_base,
        admin_password=admin_password,
        custom_auth=custom_auth,
        admin_mails_path=admin_mails_path,
        address=forward,
        preferred_limit=preferred_limit,
    )
    return [m for m in mails if isinstance(m, dict)]


def list_messages_for_icloud_alias(
    http_get: HttpGet,
    api_base: str,
    *,
    alias_email: str,
    forward_email: str = "",
    admin_password: str = "",
    custom_auth: str = "",
    admin_mails_path: str = "/admin/mails",
    hme_from_key: str = "",
) -> List[dict]:
    """Load forward mailbox mails and keep only those whose X-ICLOUD-HME p= alias.

    hme_from_key is ignored (legacy arg).
    """
    _ = hme_from_key
    alias = str(alias_email or "").strip().lower()
    forward = str(forward_email or "").strip().lower()
    if not admin_password:
        return []

    mails: List[dict] = []
    # Prefer forward mailbox (where HME actually lands)
    if forward:
        mails = list_forward_mailbox_mails(
            http_get,
            api_base,
            forward_email=forward,
            admin_password=admin_password,
            custom_auth=custom_auth,
            admin_mails_path=admin_mails_path,
        )
    if not mails:
        # also try alias address query (some workers index it)
        if alias:
            try:
                mails = list_admin_mails(
                    http_get,
                    api_base,
                    admin_password=admin_password,
                    custom_auth=custom_auth,
                    admin_mails_path=admin_mails_path,
                    address=alias,
                    preferred_limit=MAIL_LIST_LIMIT,
                )
                mails = [m for m in mails if isinstance(m, dict)]
            except Exception:
                mails = []
    if not mails:
        return []

    if not alias:
        return mails

    matched = [m for m in mails if mail_targets_hme_alias(m, alias)]
    return matched

def combine_mail_text(mail: dict) -> Tuple[str, str]:
    """Build body/subject text. This CF worker often only returns raw+address."""
    parts: List[str] = []
    subject = str(mail.get("subject") or mail.get("title") or "").strip()
    raw = str(mail.get("raw") or "").strip()

    for field in ("text", "content", "intro", "body", "snippet"):
        value = mail.get(field)
        if isinstance(value, str) and value.strip():
            parts.append(value)

    html_list = mail.get("html") or []
    if isinstance(html_list, str):
        html_list = [html_list]
    if isinstance(html_list, list):
        for html in html_list:
            if isinstance(html, str) and html.strip():
                parts.append(re.sub(r"<[^>]+>", " ", html))

    if raw:
        if not subject:
            header_blob = raw.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
            m = re.search(r"(?im)^Subject:\s*(.+)$", header_blob)
            if m:
                subject = _decode_mime_header(m.group(1).strip())
        parts.append(raw)

    if not parts:
        src = mail.get("source")
        if isinstance(src, str) and src.strip():
            parts.append(src)

    return "\n".join(parts), subject


def get_mail_detail(
    http_get: HttpGet,
    api_base: str,
    mail_id: str,
    *,
    jwt: str = "",
    admin_password: str = "",
    custom_auth: str = "",
    messages_path: str = "/api/mails",
    admin_mails_path: str = "/admin/mails",
) -> Optional[dict]:
    base = str(api_base or "").rstrip("/")
    mid = str(mail_id or "").strip()
    if not base or not mid:
        return None
    attempts: List[Tuple[str, Dict[str, str]]] = []
    token = str(jwt or "").strip()
    user_path = normalize_path(messages_path, "/api/mails")
    admin_path = normalize_path(admin_mails_path, "/admin/mails")
    if token:
        attempts.append((f"{user_path}/{mid}", user_headers(token, custom_auth=custom_auth)))
        attempts.append(
            (
                f"/user_api/mails/{mid}",
                user_headers(token, custom_auth=custom_auth, mode="x-user-token"),
            )
        )
    if admin_password:
        attempts.append(
            (
                f"{admin_path}/{mid}",
                admin_headers(admin_password, custom_auth=custom_auth),
            )
        )
    for path, headers in attempts:
        try:
            resp = http_get(f"{base}{path}", headers=headers)
            if getattr(resp, "status_code", 0) >= 400:
                continue
            data = resp.json()
            if isinstance(data, dict):
                if isinstance(data.get("result"), dict):
                    return data["result"]
                if isinstance(data.get("data"), dict):
                    return data["data"]
                if isinstance(data.get("mail"), dict):
                    return data["mail"]
                return data
        except Exception:
            continue
    return None


def list_messages(
    http_get: HttpGet,
    api_base: str,
    *,
    jwt: str = "",
    admin_password: str = "",
    custom_auth: str = "",
    target_email: str = "",
    messages_path: str = "/api/mails",
    admin_mails_path: str = "/admin/mails",
) -> List[dict]:
    """JWT first; empty inbox is success. Admin is address-filtered.

    Unfiltered /admin/mails (full-table COUNT) is only used when there is
    no JWT and no target address.
    """
    errors: List[str] = []
    if jwt:
        try:
            return list_user_mails(
                http_get,
                api_base,
                jwt,
                messages_path=messages_path,
                custom_auth=custom_auth,
                limit=MAIL_LIST_LIMIT,
            )
        except Exception as exc:
            errors.append(str(exc))

    if admin_password and target_email:
        try:
            return list_admin_mails(
                http_get,
                api_base,
                admin_password=admin_password,
                custom_auth=custom_auth,
                admin_mails_path=admin_mails_path,
                address=target_email,
                preferred_limit=MAIL_LIST_LIMIT,
            )
        except Exception as exc:
            errors.append(str(exc))

    if admin_password and not target_email:
        try:
            return list_admin_mails(
                http_get,
                api_base,
                admin_password=admin_password,
                custom_auth=custom_auth,
                admin_mails_path=admin_mails_path,
                address="",
                preferred_limit=MAIL_LIST_LIMIT,
            )
        except Exception as exc:
            errors.append(str(exc))

    if errors:
        raise Exception("cf_admin 拉取邮件失败: " + " | ".join(errors[:3]))
    return []





def fetch_mail_detail(
    http_get: HttpGet,
    api_base: str,
    *,
    mail_id: str,
    admin_password: str = "",
    custom_auth: str = "",
    admin_mails_path: str = "/admin/mails",
) -> Optional[dict]:
    """Fetch single mail detail (list APIs often omit full raw/headers)."""
    mid = str(mail_id or "").strip()
    base = str(api_base or "").rstrip("/")
    if not mid or not base:
        return None
    path = normalize_path(admin_mails_path, "/admin/mails")
    url = f"{base}{path}/{mid}"
    headers = admin_headers(str(admin_password or ""), custom_auth=custom_auth)
    try:
        resp = http_get(url, headers=headers)
        status = getattr(resp, "status_code", 0)
        if status >= 400:
            return None
        data = resp.json() if hasattr(resp, "json") else None
        if isinstance(data, dict):
            # common envelopes
            for key in ("result", "data", "mail", "message"):
                nested = data.get(key)
                if isinstance(nested, dict) and (nested.get("id") or nested.get("raw") or nested.get("text")):
                    return nested
            return data
    except Exception:
        return None
    return None



def extract_sender_address(mail: dict) -> str:
    if not isinstance(mail, dict):
        return ""
    for key in ("source", "from", "from_address", "fromAddress", "sender"):
        val = mail.get(key)
        if isinstance(val, str) and val.strip():
            text = val.strip()
            m = re.search(r"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})", text, re.I)
            if m:
                return m.group(1).lower()
            return text.lower()
    raw = str(mail.get("raw") or "")
    if raw:
        try:
            message = message_from_string(raw, policy=email_policy)
            fr = _decode_mime_header(message.get("From", ""))
            m = re.search(r"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})", fr, re.I)
            if m:
                return m.group(1).lower()
        except Exception:
            pass
    return ""



