"""Explicit owner button for metadata-only held-connection inspection."""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode

from starlette.requests import Request

from zacai.interfaces.gmail_recovery_web import GmailRecoveryWeb

_CONFIRMATION = "PAIR ORIGINAL DOMAIN AND INSPECT EXACT HELD NATIVE METADATA"
_OLD_CONFIRMATION = "PAIR ORIGINAL GMAIL DOMAIN FOR ONE RECOVERY"


class GmailNativeAbsenceWeb(GmailRecoveryWeb):
    def _form(self, request: Request, action: str, *, confirmation: str | None = None) -> str:
        if action == "/connections/gmail/recover/pair":
            confirmation = _CONFIRMATION
        result = super()._form(request, action, confirmation=confirmation)
        if action == "/connections/gmail/recover/pair":
            result = result.replace(
                "Pair my original Gmail domain for this recovery",
                "Pair and check the earlier attempt",
            )
            result = (
                "<p>This pairs your original Gmail domain for one recovery and checks metadata for a credential left by the earlier attempt. The next step repeats the metadata check and may show another Keychain prompt. Each metadata check does not read tokens or mail.</p>"
                + result
            )
        return result

    def _pair(self, request: Request, body: bytes) -> None:
        if type(body) is not bytes or len(body) > 1024:
            raise ValueError("bounded explicit metadata review required")
        fields = parse_qs(
            body.decode("ascii"), keep_blank_values=True, strict_parsing=True, max_num_fields=4
        )
        if (
            set(fields)
            != {"csrf", "reviewed_configuration_digest", "action_generation", "confirmation"}
            or any(len(v) != 1 for v in fields.values())
            or fields["confirmation"] != [_CONFIRMATION]
        ):
            raise ValueError("explicit saved-connection inspection required")
        # The original join still checks exact Host/HTTPS/Origin/current owner/CSRF,
        # and issues the same scoped new pairing. No generic pairing policy changes.
        normalized = {k: v[0] for k, v in fields.items()}
        normalized["confirmation"] = _OLD_CONFIRMATION
        super()._pair(request, urlencode(normalized).encode("ascii"))
