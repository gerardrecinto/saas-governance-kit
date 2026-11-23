import copy
from datetime import timedelta

import pytest
from lxml import etree
from saml_helpers import ACS, FIXED_NOW, IDP, SP, TestIdp

from saas_governance_kit.saml.validator import (
    SAML,
    SAMLP,
    ReplayCache,
    SamlConfig,
    SamlValidationError,
    validate_response,
)


@pytest.fixture(scope="module")
def idp():
    return TestIdp()


@pytest.fixture
def cfg(idp):
    return SamlConfig(IDP, idp.cert_pem, SP, ACS, clock_skew_seconds=60)


def run(idp, cfg, el, cache=None, request_id="req-1", now=FIXED_NOW):
    return validate_response(
        idp.to_bytes(el), cfg, cache or ReplayCache(), expected_request_id=request_id, now=now
    )


def code(idp, cfg, el, **kw):
    with pytest.raises(SamlValidationError) as e:
        run(idp, cfg, el, **kw)
    return e.value.code


def test_valid_signed_assertion(idp, cfg):
    r = run(idp, cfg, idp.sign_assertion(idp.build()))
    assert r.name_id == "alice@example.com"
    assert r.attributes["groups"] == ["eng", "oncall"]
    assert r.session_index == "s1"


def test_valid_signed_response(idp, cfg):
    assert run(idp, cfg, idp.sign_response(idp.build())).name_id == "alice@example.com"


def test_unsigned_rejected(idp, cfg):
    assert code(idp, cfg, idp.build()) == "signature_count"


def test_tampered_after_signing(idp, cfg):
    signed = idp.sign_assertion(idp.build())
    signed.find(f".//{{{SAML}}}NameID").text = "admin@example.com"
    assert code(idp, cfg, signed) == "bad_signature"


def test_signed_by_other_key(idp, cfg):
    other = TestIdp()
    assert code(idp, cfg, other.sign_assertion(idp.build())) == "bad_signature"


def test_embedded_cert_is_not_trusted(idp):
    # Config pins a different cert, so a self-signed response with its own embedded cert fails.
    other = TestIdp()
    cfg = SamlConfig(IDP, other.cert_pem, SP, ACS)
    assert code(idp, cfg, idp.sign_assertion(idp.build())) == "bad_signature"


def test_expired(idp, cfg):
    el = idp.sign_assertion(idp.build())
    assert code(idp, cfg, el, now=FIXED_NOW + timedelta(minutes=10)) == "expired"


def test_not_yet_valid_and_skew(idp, cfg):
    el = idp.sign_assertion(idp.build(not_before=FIXED_NOW + timedelta(minutes=10)))
    assert code(idp, cfg, el) == "not_yet_valid"
    # 30s early is inside the 60s skew
    el = idp.sign_assertion(idp.build(not_before=FIXED_NOW + timedelta(seconds=30)))
    assert run(idp, cfg, el).name_id


def test_expiry_edge_with_skew(idp, cfg):
    el = idp.sign_assertion(idp.build(not_on_or_after=FIXED_NOW - timedelta(seconds=30)))
    assert run(idp, cfg, el).name_id  # expired 30s ago, skew is 60s
    el = idp.sign_assertion(idp.build(not_on_or_after=FIXED_NOW - timedelta(seconds=90)))
    assert code(idp, cfg, el) == "expired"


def test_wrong_audience(idp, cfg):
    assert code(idp, cfg, idp.sign_assertion(idp.build(audience="https://evil/sp"))) == (
        "audience_mismatch"
    )


def test_wrong_destination(idp, cfg):
    el = idp.sign_assertion(idp.build(destination="https://evil/acs"))
    assert code(idp, cfg, el) == "destination_mismatch"


def test_wrong_in_response_to(idp, cfg):
    el = idp.sign_assertion(idp.build(in_response_to="other"))
    assert code(idp, cfg, el) == "in_response_to_mismatch"


def test_idp_initiated_blocked_by_default_and_allowed_by_flag(idp, cfg):
    el = idp.sign_assertion(idp.build(in_response_to=""))
    assert code(idp, cfg, el, request_id=None) == "unsolicited_response"
    cfg.allow_idp_initiated = True
    el = idp.sign_assertion(idp.build())
    assert run(idp, cfg, el, request_id=None).name_id


def test_wrong_issuer(idp, cfg):
    el = idp.sign_assertion(idp.build(issuer="https://evil/idp"))
    assert code(idp, cfg, el) == "issuer_mismatch"


def test_replay(idp, cfg):
    cache = ReplayCache()
    el = idp.sign_assertion(idp.build())
    run(idp, cfg, el, cache=cache)
    assert code(idp, cfg, el, cache=cache) == "replay"


def test_failed_validation_does_not_burn_replay_cache(idp, cfg):
    cache = ReplayCache()
    el = idp.sign_assertion(idp.build(audience="https://evil/sp", assertion_id="_same"))
    assert code(idp, cfg, el, cache=cache) == "audience_mismatch"
    assert cache._seen == {}


def test_xsw_forged_assertion_added_next_to_signed_one(idp, cfg):
    signed = idp.sign_assertion(idp.build())
    forged = copy.deepcopy(signed.find(f"{{{SAML}}}Assertion"))
    forged.find(f".//{{{SAML}}}NameID").text = "admin@example.com"
    for sig in forged.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        forged.remove(sig)
    forged.set("ID", "_forged")
    signed.insert(2, forged)
    assert code(idp, cfg, signed) == "assertion_count"


def test_xsw_signed_assertion_hidden_in_extensions(idp, cfg):
    signed = idp.sign_assertion(idp.build())
    original = signed.find(f"{{{SAML}}}Assertion")
    forged = copy.deepcopy(original)
    forged.find(f".//{{{SAML}}}NameID").text = "admin@example.com"
    forged.set("ID", "_forged")
    for sig in forged.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        forged.remove(sig)
    ext = etree.SubElement(signed, f"{{{SAMLP}}}Extensions")
    ext.append(original)  # moves the signed one away
    signed.append(forged)
    assert code(idp, cfg, signed) in {"assertion_count", "signature_location", "bad_signature"}


def test_xsw_signed_response_with_unsigned_forged_assertion_swapped(idp, cfg):
    # Response signature covers the Response; replacing the Assertion breaks the digest.
    signed = idp.sign_response(idp.build())
    signed.find(f".//{{{SAML}}}NameID").text = "admin@example.com"
    assert code(idp, cfg, signed) == "bad_signature"


def test_duplicate_ids_rejected(idp, cfg):
    signed = idp.sign_assertion(idp.build())
    signed.find(f"{{{SAML}}}Issuer").set("ID", signed.get("ID"))
    assert code(idp, cfg, signed) == "duplicate_id"


def test_doctype_rejected(idp, cfg):
    xml = idp.to_bytes(idp.sign_assertion(idp.build()))
    evil = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "y">]>' + xml
    with pytest.raises(SamlValidationError) as e:
        validate_response(evil, cfg, ReplayCache(), "req-1", FIXED_NOW)
    assert e.value.code == "dtd_forbidden"


def test_garbage_and_wrong_root(idp, cfg):
    with pytest.raises(SamlValidationError) as e:
        validate_response(b"<not xml", cfg, ReplayCache(), "req-1", FIXED_NOW)
    assert e.value.code == "bad_xml"
    with pytest.raises(SamlValidationError) as e:
        validate_response(b"<a/>", cfg, ReplayCache(), "req-1", FIXED_NOW)
    assert e.value.code == "not_response"


def test_failed_status(idp, cfg):
    el = idp.build()
    el.find(f".//{{{SAMLP}}}StatusCode").set(
        "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder"
    )
    assert code(idp, cfg, idp.sign_assertion(el)) == "status_failed"
