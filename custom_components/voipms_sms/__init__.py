import asyncio
import base64
import logging
import mimetypes
import os

import aiohttp
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.aiohttp_client import async_get_clientsession

DOMAIN = "voipms_sms"
_LOGGER = logging.getLogger(__name__)

REST_ENDPOINT = "https://voip.ms/api/v1/rest.php"

SERVICE_SEND_SMS = "send_sms"
SERVICE_SEND_MMS = "send_mms"

CONF_ACCOUNT_USER = "account_user"
CONF_API_PASSWORD = "api_password"
CONF_SENDER_DID = "sender_did"

# YAML configuration schema (domain-keyed)
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

SERVICE_SCHEMA_SMS = vol.Schema(
    {
        vol.Required("recipient"): cv.string,
        vol.Required("message"): cv.string,
    }
)

SERVICE_SCHEMA_MMS = vol.Schema(
    {
        vol.Required("recipient"): cv.string,
        vol.Required("message"): cv.string,
        vol.Required("image_path"): cv.string,
    }
)


async def _get_base64_data(image_path: str) -> str:
    def encode() -> str:
        mime_type, _ = mimetypes.guess_type(image_path)
        if not mime_type:
            mime_type = "application/octet-stream"
        with open(image_path, "rb") as f:
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
            text = await resp.text()
            return resp.status, text


async def _handle_send_sms(hass: HomeAssistant, conf: dict, call: ServiceCall) -> None:
    recipient = call.data.get("recipient")
    message = call.data.get("message")

    form_data = {
        "api_username": conf[CONF_ACCOUNT_USER],
        "api_password": conf[CONF_API_PASSWORD],
        "did": conf[CONF_SENDER_DID],
        "dst": recipient,
        "message": message,
        "method": "sendSMS",
    }

    status, body = await _post_voipms(hass, form_data)

    if status == 200:
        _LOGGER.info("voipms_sms: sendSMS response: %s", body)
    else:
        _LOGGER.error("voipms_sms: sendSMS failed (%s): %s", status, body)


async def _handle_send_mms(hass: HomeAssistant, conf: dict, call: ServiceCall) -> None:
    recipient = call.data.get("recipient")
    message = call.data.get("message")
    image_path = call.data.get("image_path")

    if not os.path.exists(image_path):
        _LOGGER.error("voipms_sms: Image file not found: %s", image_path)
        return

    media_data = await _get_base64_data(image_path)

    form_data = {
        "api_username": conf[CONF_ACCOUNT_USER],
        "api_password": conf[CONF_API_PASSWORD],
        "did": conf[CONF_SENDER_DID],
        "dst": recipient,
        "message": message,
        "method": "sendMMS",
        "media1": media_data,
    }

    status, body = await _post_voipms(hass, form_data)

    if status == 200:
        _LOGGER.info("voipms_sms: sendMMS response: %s", body)
    else:
        _LOGGER.error("voipms_sms: sendMMS failed (%s): %s", status, body)


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the VoIP.ms SMS integration (YAML)."""
    if DOMAIN not in config:
        return True

    conf = config[DOMAIN]

    async def handle_send_sms(call: ServiceCall) -> None:
        await _handle_send_sms(hass, conf, call)

    async def handle_send_mms(call: ServiceCall) -> None:
        await _handle_send_mms(hass, conf, call)

    hass.services.async_register(DOMAIN, SERVICE_SEND_SMS, handle_send_sms, schema=SERVICE_SCHEMA_SMS)
    hass.services.async_register(DOMAIN, SERVICE_SEND_MMS, handle_send_mms, schema=SERVICE_SCHEMA_MMS)

    _LOGGER.info("voipms_sms: services registered (%s.%s, %s.%s)", DOMAIN, SERVICE_SEND_SMS, DOMAIN, SERVICE_SEND_MMS)
    return True
