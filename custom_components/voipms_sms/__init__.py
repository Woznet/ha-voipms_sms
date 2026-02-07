import asyncio
import base64
import json
import logging
import mimetypes
import re
from pathlib import Path
from typing import Any, Iterable

import aiohttp
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.aiohttp_client import async_get_clientsession

DOMAIN = "voipms_sms"
_LOGGER = logging.getLogger(__name__)

REST_ENDPOINT = "https://voip.ms/api/v1/rest.php"

SERVICE_SEND_MESSAGE = "send_message"

CONF_ACCOUNT_USER = "account_user"
CONF_API_PASSWORD = "api_password"
CONF_SENDER_DID = "sender_did"

SMS_MAX_CHARS = 160
MMS_MAX_CHARS = 2048
MMS_MAX_BYTES = 1300 * 1024  # 1300 KB
MMS_ALLOWED_EXTS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".mp3",
    ".wav",
    ".midi",
    ".mp4",
    ".3gp",
}
MMS_MAX_ATTACHMENTS = 3
MAX_RECIPIENTS = 10

_RECIPIENT_RE = re.compile(r"^\d{10}$")

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Required(CONF_ACCOUNT_USER): cv.string,
                vol.Required(CONF_API_PASSWORD): cv.string,
                vol.Required(CONF_SENDER_DID): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

SERVICE_SCHEMA_SEND_MESSAGE = vol.Schema(
    {
        vol.Required("recipient"): cv.string,  # may contain 1..10 numbers separated by commas/whitespace/newlines
        vol.Required("message"): cv.string,
        vol.Optional("attachments"): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional("split_long", default=False): cv.boolean,
        vol.Optional("delay_ms", default=250): vol.All(vol.Coerce(int), vol.Range(min=0, max=5000)),
        vol.Optional("max_parts", default=10): vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
        vol.Optional("continue_on_error", default=True): cv.boolean,
        vol.Optional("recipient_delay_ms", default=0): vol.All(vol.Coerce(int), vol.Range(min=0, max=5000)),
    }
)


def _normalize_nanp_number(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


def _parse_recipients(raw: str | None) -> list[str]:
    if not raw:
        return []
    # allow: commas, semicolons, whitespace, newlines
    parts = [p for p in re.split(r"[,\s;]+", str(raw).strip()) if p]
    out: list[str] = []
    seen: set[str] = set()
    for p in parts:
        digits = _normalize_nanp_number(p)
        if digits and digits not in seen:
            seen.add(digits)
            out.append(digits)
    return out


def _validate_recipient(recipient_digits: str) -> bool:
    return bool(_RECIPIENT_RE.match(recipient_digits))


def _parse_voipms_response(body: str) -> dict[str, Any] | None:
    try:
        return json.loads(body)
    except Exception:
        return None


def _mask_did(did: str | None) -> str:
    if not did:
        return "<none>"
    digits = re.sub(r"\D", "", did)
    return f"***{digits[-4:]}" if len(digits) >= 4 else "****"


def _mask_recipient(dst: str | None) -> str:
    if not dst:
        return "<none>"
    return f"***{dst[-4:]}" if len(dst) == 10 else dst


def _coerce_attachments(call: ServiceCall) -> list[str]:
    raw = call.data.get("attachments")
    paths = [str(x) for x in raw] if isinstance(raw, list) else []
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _validate_attachments(paths: Iterable[str]) -> tuple[bool, str]:
    paths_list = list(paths)
    if len(paths_list) > MMS_MAX_ATTACHMENTS:
        return False, f"Too many attachments ({len(paths_list)} > {MMS_MAX_ATTACHMENTS})"

    for p in paths_list:
        path = Path(p)  # Use pathlib
        if not path.is_absolute():
            return False, f"Attachment path must be absolute: {p}"

        try:
            stat = path.stat()  # Single call - atomic check
        except FileNotFoundError:
            return False, f"Attachment file not found: {p}"
        except OSError as e:
            return False, f"Failed to access attachment file: {p} ({e})"

        if not stat.st_mode & 0o100000:  # S_IFREG - is regular file
            return False, f"Attachment path is not a file: {p}"

        ext = path.suffix.lower()
        if ext not in MMS_ALLOWED_EXTS:
            return False, f"Unsupported attachment type '{ext}' for file: {p}"

        if stat.st_size > MMS_MAX_BYTES:
            return False, f"Attachment too large ({stat.st_size} bytes > {MMS_MAX_BYTES} bytes): {p}"

    return True, ""


def _split_message(message: str, chunk_size: int) -> list[str]:
    if not message:
        return [""]
    return [message[i : i + chunk_size] for i in range(0, len(message), chunk_size)]


async def _get_base64_data(path: str) -> str:
    def encode() -> str:
        mime_type, _ = mimetypes.guess_type(path)
        if not mime_type:
            mime_type = "application/octet-stream"
        with open(path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode()
        return f"data:{mime_type};base64,{encoded}"

    return await asyncio.to_thread(encode)


async def _post_voipms(hass: HomeAssistant, form_fields: dict) -> tuple[int, str]:
    session = async_get_clientsession(hass)
    timeout = aiohttp.ClientTimeout(total=30)

    with aiohttp.MultipartWriter("form-data") as mp:
        for key, value in form_fields.items():
            part = mp.append(str(value))
            part.set_content_disposition("form-data", name=key)

        async with session.post(REST_ENDPOINT, data=mp, timeout=timeout) as resp:
            return resp.status, await resp.text()


async def _send_sms_once(hass: HomeAssistant, conf: dict, recipient: str, message: str) -> bool:
    sender_did = re.sub(r"\D", "", str(conf.get(CONF_SENDER_DID, "")).strip())
    form_data = {
        "api_username": conf[CONF_ACCOUNT_USER],
        "api_password": conf[CONF_API_PASSWORD],
        "did": sender_did,
        "dst": recipient,
        "message": message,
        "method": "sendSMS",
    }

    try:
        status, body = await _post_voipms(hass, form_data)
    except Exception:
        _LOGGER.exception("voipms_sms: sendSMS request failed (to=%s)", _mask_recipient(recipient))
        return False

    parsed = _parse_voipms_response(body)
    if status != 200:
        _LOGGER.error(
            "voipms_sms: sendSMS HTTP %s (to=%s): %s",
            status,
            _mask_recipient(recipient),
            body,
        )
        return False

    if parsed and str(parsed.get("status", "")).lower() not in ("success", "ok", "200"):
        _LOGGER.error(
            "voipms_sms: sendSMS API error (to=%s): %s",
            _mask_recipient(recipient),
            body,
        )
        return False

    _LOGGER.info("voipms_sms: sendSMS accepted (to=%s)", _mask_recipient(recipient))
    return True


async def _send_mms_once(
    hass: HomeAssistant,
    conf: dict,
    recipient: str,
    message: str,
    attachments: list[str],
) -> bool:
    sender_did = re.sub(r"\D", "", str(conf.get(CONF_SENDER_DID, "")).strip())

    form_data: dict[str, Any] = {
        "api_username": conf[CONF_ACCOUNT_USER],
        "api_password": conf[CONF_API_PASSWORD],
        "did": sender_did,
        "dst": recipient,
        "message": message,
        "method": "sendMMS",
    }

    if attachments:
        for idx, path in enumerate(attachments[:MMS_MAX_ATTACHMENTS], start=1):
            media_data = await _get_base64_data(path)
            form_data[f"media{idx}"] = media_data

    try:
        status, body = await _post_voipms(hass, form_data)
    except Exception:
        _LOGGER.exception("voipms_sms: sendMMS request failed (to=%s)", _mask_recipient(recipient))
        return False

    parsed = _parse_voipms_response(body)
    if status != 200:
        _LOGGER.error(
            "voipms_sms: sendMMS HTTP %s (to=%s): %s",
            status,
            _mask_recipient(recipient),
            body,
        )
        return False

    if parsed and str(parsed.get("status", "")).lower() not in ("success", "ok", "200"):
        _LOGGER.error(
            "voipms_sms: sendMMS API error (to=%s): %s",
            _mask_recipient(recipient),
            body,
        )
        return False

    _LOGGER.info("voipms_sms: sendMMS accepted (to=%s)", _mask_recipient(recipient))
    return True


async def _dispatch_single_recipient(
    hass: HomeAssistant,
    conf: dict,
    recipient: str,
    message: str,
    attachments: list[str],
    split_long: bool,
    delay_ms: int,
    max_parts: int,
) -> bool:
    msg_len = len(message)
    use_mms = bool(attachments) or msg_len > SMS_MAX_CHARS

    if not use_mms:
        return await _send_sms_once(hass, conf, recipient, message)

    if msg_len <= MMS_MAX_CHARS:
        return await _send_mms_once(hass, conf, recipient, message, attachments)

    if not split_long:
        _LOGGER.error(
            "voipms_sms: Message too long for MMS (%s > %s) and split_long is false (to=%s)",
            msg_len,
            MMS_MAX_CHARS,
            _mask_recipient(recipient),
        )
        return False

    if attachments:
        _LOGGER.error(
            "voipms_sms: split_long enabled but attachments provided; not supported (to=%s)",
            _mask_recipient(recipient),
        )
        return False

    parts = _split_message(message, MMS_MAX_CHARS)
    if len(parts) > max_parts:
        _LOGGER.error(
            "voipms_sms: Message split into %s parts (max_parts=%s). Refusing (to=%s).",
            len(parts),
            max_parts,
            _mask_recipient(recipient),
        )
        return False

    total = len(parts)
    _LOGGER.warning(
        "voipms_sms: Splitting long message into %s MMS parts (to=%s)",
        total,
        _mask_recipient(recipient),
    )

    for i, part in enumerate(parts, start=1):
        prefix = f"[{i}/{total}] "
        payload = (prefix + part)[:MMS_MAX_CHARS]
        ok = await _send_mms_once(hass, conf, recipient, payload, [])
        if not ok:
            _LOGGER.error(
                "voipms_sms: MMS part %s/%s failed (to=%s)",
                i,
                total,
                _mask_recipient(recipient),
            )
            return False
        if delay_ms > 0 and i < total:
            await asyncio.sleep(delay_ms / 1000.0)

    return True


async def _handle_send_message(hass: HomeAssistant, conf: dict, call: ServiceCall) -> None:
    recipients_raw = call.data.get("recipient")
    message_raw = call.data.get("message")

    recipients = _parse_recipients(recipients_raw)
    if not recipients:
        _LOGGER.error("voipms_sms: No recipients provided")
        return

    if len(recipients) > MAX_RECIPIENTS:
        _LOGGER.error("voipms_sms: Too many recipients (%s > %s)", len(recipients), MAX_RECIPIENTS)
        return

    invalid = [r for r in recipients if not _validate_recipient(r)]
    if invalid:
        _LOGGER.error(
            "voipms_sms: Invalid recipient(s) (expected US/CA 10 digits): %s",
            ", ".join(invalid),
        )
        return

    message = "" if message_raw is None else str(message_raw)
    if len(message) == 0:
        _LOGGER.error("voipms_sms: Message is empty")
        return

    attachments = _coerce_attachments(call)
    if attachments:
        ok, err = _validate_attachments(attachments)
        if not ok:
            _LOGGER.error("voipms_sms: Attachment validation failed: %s", err)
            return

    split_long = bool(call.data.get("split_long", False))
    delay_ms = int(call.data.get("delay_ms", 250))
    max_parts = int(call.data.get("max_parts", 10))
    continue_on_error = bool(call.data.get("continue_on_error", True))
    recipient_delay_ms = int(call.data.get("recipient_delay_ms", 0))

    _LOGGER.info(
        "voipms_sms: send_message start (recipients=%s len=%s attachments=%s split_long=%s)",
        len(recipients),
        len(message),
        len(attachments),
        split_long,
    )

    successes = 0
    failures = 0

    for idx, r in enumerate(recipients, start=1):
        _LOGGER.debug(
            "voipms_sms: Sending to recipient %s/%s (%s)",
            idx,
            len(recipients),
            _mask_recipient(r),
        )

        ok = await _dispatch_single_recipient(
            hass=hass,
            conf=conf,
            recipient=r,
            message=message,
            attachments=attachments,
            split_long=split_long,
            delay_ms=delay_ms,
            max_parts=max_parts,
        )

        if ok:
            successes += 1
        else:
            failures += 1
            if not continue_on_error:
                _LOGGER.error("voipms_sms: Halting on first failure (to=%s)", _mask_recipient(r))
                break

        if recipient_delay_ms > 0 and idx < len(recipients):
            await asyncio.sleep(recipient_delay_ms / 1000.0)

    _LOGGER.info("voipms_sms: send_message complete (success=%s failed=%s)", successes, failures)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    if DOMAIN not in config:
        return True

    conf = config[DOMAIN]

    async def handle_send_message(call: ServiceCall) -> None:
        await _handle_send_message(hass, conf, call)

    hass.services.async_register(
        DOMAIN,
        SERVICE_SEND_MESSAGE,
        handle_send_message,
        schema=SERVICE_SCHEMA_SEND_MESSAGE,
    )
    _LOGGER.info("voipms_sms: services registered (%s.%s)", DOMAIN, SERVICE_SEND_MESSAGE)
    return True
