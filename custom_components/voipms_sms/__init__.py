import asyncio
import base64
import json
import logging
import mimetypes
import os
import re
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
MMS_ALLOWED_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".mp3", ".wav", ".midi", ".mp4", ".3gp"}
MMS_MAX_ATTACHMENTS = 3

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
        vol.Required("recipient"): cv.string,
        vol.Required("message"): cv.string,
        vol.Optional("attachments"): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional("split_long", default=False): cv.boolean,
        vol.Optional("delay_ms", default=250): vol.All(vol.Coerce(int), vol.Range(min=0, max=5000)),
        vol.Optional("max_parts", default=10): vol.All(vol.Coerce(int), vol.Range(min=1, max=50)),
    }
)


def _normalize_recipient(value: str | None) -> str | None:
    if value is None:
        return None
    digits = re.sub(r"\D", "", str(value))
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return digits


def _validate_recipient(recipient_digits: str | None) -> bool:
    return bool(recipient_digits and _RECIPIENT_RE.match(recipient_digits))


def _parse_voipms_response(body: str) -> dict[str, Any] | None:
    try:
        return json.loads(body)
    except Exception:
        return None


def _mask_did(did: str | None) -> str:
    if not did:
        return "<none>"
    digits = re.sub(r"\D", "", did)
    if len(digits) < 4:
        return "****"
    return f"***{digits[-4:]}"


def _mask_recipient(dst: str | None) -> str:
    if not dst:
        return "<none>"
    if len(dst) != 10:
        return dst
    return f"***{dst[-4:]}"


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
        if not os.path.isabs(p):
            return False, f"Attachment path must be absolute: {p}"
        if not os.path.exists(p):
            return False, f"Attachment file not found: {p}"
        if not os.path.isfile(p):
            return False, f"Attachment path is not a file: {p}"
        ext = os.path.splitext(p)[1].lower()
        if ext not in MMS_ALLOWED_EXTS:
            return False, f"Unsupported attachment type '{ext}' for file: {p}"
        try:
            size = os.path.getsize(p)
        except Exception:
            return False, f"Failed to stat attachment file: {p}"
        if size > MMS_MAX_BYTES:
            return False, f"Attachment too large ({size} bytes > {MMS_MAX_BYTES} bytes): {p}"
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
        _LOGGER.exception("voipms_sms: sendSMS request failed")
        return False

    parsed = _parse_voipms_response(body)
    if status != 200:
        _LOGGER.error("voipms_sms: sendSMS HTTP %s: %s", status, body)
        return False

    if parsed and str(parsed.get("status", "")).lower() not in ("success", "ok", "200"):
        _LOGGER.error("voipms_sms: sendSMS API error: %s", body)
        return False

    _LOGGER.info("voipms_sms: sendSMS accepted: %s", body)
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
        _LOGGER.exception("voipms_sms: sendMMS request failed")
        return False

    parsed = _parse_voipms_response(body)
    if status != 200:
        _LOGGER.error("voipms_sms: sendMMS HTTP %s: %s", status, body)
        return False

    if parsed and str(parsed.get("status", "")).lower() not in ("success", "ok", "200"):
        _LOGGER.error("voipms_sms: sendMMS API error: %s", body)
        return False

    _LOGGER.info("voipms_sms: sendMMS accepted: %s", body)
    return True


async def _dispatch_message(
    hass: HomeAssistant,
    conf: dict,
    recipient: str,
    message: str,
    attachments: list[str],
    split_long: bool,
    delay_ms: int,
    max_parts: int,
) -> None:
    msg_len = len(message)
    use_mms = bool(attachments) or msg_len > SMS_MAX_CHARS

    if not use_mms:
        _LOGGER.debug("voipms_sms: Using SMS (to=%s from=%s len=%s)", _mask_recipient(recipient), _mask_did(conf.get(CONF_SENDER_DID)), msg_len)
        ok = await _send_sms_once(hass, conf, recipient, message)
        if not ok:
            _LOGGER.error("voipms_sms: SMS send failed (to=%s)", _mask_recipient(recipient))
        return

    if msg_len <= MMS_MAX_CHARS:
        _LOGGER.debug(
            "voipms_sms: Using MMS (to=%s from=%s len=%s attachments=%s)",
            _mask_recipient(recipient),
            _mask_did(conf.get(CONF_SENDER_DID)),
            msg_len,
            len(attachments),
        )
        ok = await _send_mms_once(hass, conf, recipient, message, attachments)
        if not ok:
            _LOGGER.error("voipms_sms: MMS send failed (to=%s)", _mask_recipient(recipient))
        return

    if not split_long:
        _LOGGER.error("voipms_sms: Message too long for MMS (%s > %s) and split_long is false", msg_len, MMS_MAX_CHARS)
        return

    if attachments:
        _LOGGER.error("voipms_sms: split_long is enabled but attachments were provided; splitting with attachments is not supported")
        return

    parts = _split_message(message, MMS_MAX_CHARS)
    if len(parts) > max_parts:
        _LOGGER.error("voipms_sms: Message split into %s parts (max_parts=%s). Refusing to send.", len(parts), max_parts)
        return

    _LOGGER.warning(
        "voipms_sms: Splitting long message into %s MMS parts (to=%s total_len=%s)",
        len(parts),
        _mask_recipient(recipient),
        msg_len,
    )

    total = len(parts)
    for i, part in enumerate(parts, start=1):
        prefix = f"[{i}/{total}] "
        payload = (prefix + part)[:MMS_MAX_CHARS]
        _LOGGER.debug("voipms_sms: Sending MMS part %s/%s (len=%s)", i, total, len(payload))
        ok = await _send_mms_once(hass, conf, recipient, payload, [])
        if not ok:
            _LOGGER.error("voipms_sms: MMS part %s/%s failed (to=%s)", i, total, _mask_recipient(recipient))
            return
        if delay_ms > 0 and i < total:
            await asyncio.sleep(delay_ms / 1000.0)


async def _handle_send_message(hass: HomeAssistant, conf: dict, call: ServiceCall) -> None:
    recipient_raw = call.data.get("recipient")
    message_raw = call.data.get("message")

    recipient = _normalize_recipient(recipient_raw)
    if not _validate_recipient(recipient):
        _LOGGER.error("voipms_sms: Invalid recipient '%s' (expected US/CA 10 digits)", recipient_raw)
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

    _LOGGER.debug(
        "voipms_sms: send_message dispatch (to=%s len=%s attachments=%s split_long=%s)",
        _mask_recipient(recipient),
        len(message),
        len(attachments),
        split_long,
    )

    await _dispatch_message(
        hass=hass,
        conf=conf,
        recipient=recipient,
        message=message,
        attachments=attachments,
        split_long=split_long,
        delay_ms=delay_ms,
        max_parts=max_parts,
    )


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    if DOMAIN not in config:
        return True

    conf = config[DOMAIN]

    async def handle_send_message(call: ServiceCall) -> None:
        await _handle_send_message(hass, conf, call)

    hass.services.async_register(DOMAIN, SERVICE_SEND_MESSAGE, handle_send_message, schema=SERVICE_SCHEMA_SEND_MESSAGE)
    _LOGGER.info("voipms_sms: services registered (%s.%s)", DOMAIN, SERVICE_SEND_MESSAGE)
    return True
