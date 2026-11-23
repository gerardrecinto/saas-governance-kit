"""SAML 2.0 SP-side Response/Assertion validator (Web Browser SSO profile, HTTP-POST binding)."""

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from lxml import etree
from signxml import XMLVerifier
from signxml.exceptions import InvalidSignature

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
NS = {"samlp": SAMLP, "saml": SAML, "ds": DS}
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


class SamlValidationError(Exception):
    """Raised for any reason an assertion must not be trusted. `code` is stable for logs/tests."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class SamlConfig:
    idp_entity_id: str
    idp_cert_pem: bytes | str
    sp_entity_id: str
    acs_url: str
    clock_skew_seconds: int = 120
    allow_idp_initiated: bool = False


@dataclass
class SamlResult:
    name_id: str
    attributes: dict[str, list[str]]
    assertion_id: str
    session_index: str | None
    not_on_or_after: datetime


@dataclass
class ReplayCache:
    """In-memory assertion ID cache. Use a shared store (Redis, DB) with multiple SP instances."""

    _seen: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def check_and_add(self, assertion_id: str, expires_at: float, now: float | None = None) -> bool:
        """Return True if new, False if already seen."""
        now = time.time() if now is None else now
        with self._lock:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            if assertion_id in self._seen:
                return False
            self._seen[assertion_id] = expires_at
            return True


def parse_time(value: str) -> datetime:
    try:
        v = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(v)
    except ValueError:
        raise SamlValidationError("bad_time", f"Unparseable timestamp {value!r}") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _parse_xml(raw: bytes) -> etree._Element:
    parser = etree.XMLParser(
        resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
        huge_tree=False, remove_comments=False,
    )  # fmt: skip
    try:
        root = etree.fromstring(raw, parser)
    except etree.XMLSyntaxError as e:
        raise SamlValidationError("bad_xml", str(e)) from None
    if root.getroottree().docinfo.doctype:
        raise SamlValidationError("dtd_forbidden", "DOCTYPE is not allowed in SAML messages")
    return root


def _check_unique_ids(root: etree._Element) -> None:
    ids = [e.get("ID") for e in root.iter() if isinstance(e.tag, str) and e.get("ID")]
    if len(ids) != len(set(ids)):
        raise SamlValidationError("duplicate_id", "Duplicate ID attributes (possible wrapping)")


def validate_response(
    raw: bytes,
    config: SamlConfig,
    replay_cache: ReplayCache,
    expected_request_id: str | None = None,
    now: datetime | None = None,
) -> SamlResult:
    now = now or datetime.now(UTC)
    skew = timedelta(seconds=config.clock_skew_seconds)
    root = _parse_xml(raw)
    if root.tag != f"{{{SAMLP}}}Response":
        raise SamlValidationError("not_response", "Root element is not samlp:Response")
    _check_unique_ids(root)

    # Structural checks on the outer Response. Trust decisions below use only signed content.
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != STATUS_SUCCESS:
        raise SamlValidationError("status_failed", "Response status is not Success")
    if root.get("Version") != "2.0":
        raise SamlValidationError("bad_version", "Only SAML 2.0 is supported")
    if root.find(".//saml:EncryptedAssertion", NS) is not None:
        raise SamlValidationError("encrypted_unsupported", "EncryptedAssertion is not supported")
    if len(root.findall(".//saml:Assertion", NS)) != 1:
        raise SamlValidationError("assertion_count", "Exactly one Assertion is required")

    destination = root.get("Destination")
    if destination != config.acs_url:
        raise SamlValidationError("destination_mismatch", f"Destination {destination!r}")

    irt = root.get("InResponseTo")
    if expected_request_id is not None:
        if irt != expected_request_id:
            raise SamlValidationError("in_response_to_mismatch", f"InResponseTo {irt!r}")
    elif not config.allow_idp_initiated:
        raise SamlValidationError("unsolicited_response", "IdP-initiated SSO is disabled")

    signed = _verify_signature(root, config)
    assertion = (
        signed if signed.tag == f"{{{SAML}}}Assertion" else signed.find("saml:Assertion", NS)
    )
    if assertion is None:
        raise SamlValidationError("unsigned_assertion", "Assertion is not covered by a signature")

    return _check_assertion(assertion, config, replay_cache, expected_request_id, now, skew)


def _verify_signature(root: etree._Element, config: SamlConfig) -> etree._Element:
    """Verify exactly one signature over the Response or the Assertion, return the signed element."""
    sigs = root.findall(".//ds:Signature", NS)
    if len(sigs) != 1:
        raise SamlValidationError("signature_count", f"Expected 1 signature, found {len(sigs)}")
    parent = sigs[0].getparent()
    if parent is not root and parent.tag != f"{{{SAML}}}Assertion":
        raise SamlValidationError("signature_location", "Signature is not on Response or Assertion")
    if parent.tag == f"{{{SAML}}}Assertion" and parent.getparent() is not root:
        raise SamlValidationError("signature_location", "Assertion is not a direct Response child")
    try:
        result = XMLVerifier().verify(
            root, x509_cert=config.idp_cert_pem, expect_references=1, id_attribute="ID"
        )
    except InvalidSignature as e:
        raise SamlValidationError("bad_signature", str(e)) from None
    except Exception as e:  # signxml raises several types for malformed signature structures
        raise SamlValidationError("bad_signature", f"{type(e).__name__}: {e}") from None
    signed = result.signed_xml
    if signed.get("ID") != parent.get("ID"):
        raise SamlValidationError("signature_reference", "Signature covers a different element")
    return signed


def _text(el: etree._Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def _check_assertion(assertion, config, replay_cache, request_id, now, skew) -> SamlResult:
    if _text(assertion.find("saml:Issuer", NS)) != config.idp_entity_id:
        raise SamlValidationError("issuer_mismatch", "Assertion Issuer is not the configured IdP")

    # Conditions: validity window and audience
    cond = assertion.find("saml:Conditions", NS)
    if cond is None:
        raise SamlValidationError("no_conditions", "Conditions element is required")
    nb, noa = cond.get("NotBefore"), cond.get("NotOnOrAfter")
    if nb and now + skew < parse_time(nb):
        raise SamlValidationError("not_yet_valid", f"NotBefore {nb}")
    if not noa:
        raise SamlValidationError("no_expiry", "Conditions NotOnOrAfter is required")
    expiry = parse_time(noa)
    if now - skew >= expiry:
        raise SamlValidationError("expired", f"NotOnOrAfter {noa}")
    audiences = [_text(a) for a in cond.findall("saml:AudienceRestriction/saml:Audience", NS)]
    if config.sp_entity_id not in audiences:
        raise SamlValidationError("audience_mismatch", f"Audiences {audiences}")

    # Subject confirmation (bearer)
    subj = assertion.find("saml:Subject", NS)
    name_id = _text(subj.find("saml:NameID", NS)) if subj is not None else ""
    if not name_id:
        raise SamlValidationError("no_name_id", "Subject NameID is required")
    ok = False
    for sc in subj.findall("saml:SubjectConfirmation", NS):
        if sc.get("Method") != BEARER:
            continue
        scd = sc.find("saml:SubjectConfirmationData", NS)
        if scd is None or scd.get("Recipient") != config.acs_url:
            continue
        if request_id is not None and scd.get("InResponseTo") != request_id:
            continue
        scd_noa = scd.get("NotOnOrAfter")
        if not scd_noa or now - skew >= parse_time(scd_noa):
            continue
        ok = True
    if not ok:
        raise SamlValidationError("subject_confirmation", "No valid bearer SubjectConfirmation")

    authn = assertion.find("saml:AuthnStatement", NS)
    session_index = authn.get("SessionIndex") if authn is not None else None
    sess_noa = authn.get("SessionNotOnOrAfter") if authn is not None else None
    if sess_noa and now - skew >= parse_time(sess_noa):
        raise SamlValidationError("session_expired", f"SessionNotOnOrAfter {sess_noa}")

    attrs: dict[str, list[str]] = {}
    for a in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        attrs.setdefault(a.get("Name", ""), []).extend(
            _text(v) for v in a.findall("saml:AttributeValue", NS)
        )

    assertion_id = assertion.get("ID")
    if not assertion_id:
        raise SamlValidationError("no_id", "Assertion ID is required")
    keep_until = (expiry + skew).timestamp()
    if not replay_cache.check_and_add(assertion_id, keep_until, now.timestamp()):
        raise SamlValidationError("replay", f"Assertion {assertion_id} was already used")
    return SamlResult(name_id, attrs, assertion_id, session_index, expiry)
