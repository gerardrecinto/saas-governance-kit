import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from saas_governance_kit.oidc.validator import (
    IdTokenError,
    JwksClient,
    OidcConfig,
    validate_id_token,
)

ISS, CID, NONCE = "https://idp.test", "client-1", "n-0S6"
NOW = 1_800_000_000.0


def b64(n: int) -> str:
    return (
        base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    )


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_of(key, kid="k1", **extra):
    pub = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "n": b64(pub.n), "e": b64(pub.e), **extra}


def claims(**over):
    base = {"iss": ISS, "aud": CID, "sub": "u1", "exp": NOW + 300, "iat": NOW - 5, "nonce": NONCE}
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def mint(key, c=None, alg="RS256", kid="k1"):
    return jwt.encode(c or claims(), key, algorithm=alg, headers={"kid": kid})


@pytest.fixture
def cfg():
    return OidcConfig(ISS, CID, leeway_seconds=10)


def err(token, cfg, jwks, nonce=NONCE):
    with pytest.raises(IdTokenError) as e:
        validate_id_token(token, cfg, jwks, nonce, now=NOW)
    return e.value.code


def test_valid(rsa_key, cfg):
    jwks = {"keys": [jwk_of(rsa_key)]}
    out = validate_id_token(mint(rsa_key), cfg, jwks, NONCE, now=NOW)
    assert out["sub"] == "u1"


def test_es256_valid(cfg):
    key = ec.generate_private_key(ec.SECP256R1())
    n = key.public_key().public_numbers()
    jwk = {"kty": "EC", "crv": "P-256", "kid": "e1", "x": b64(n.x), "y": b64(n.y)}
    tok = mint(key, alg="ES256", kid="e1")
    assert validate_id_token(tok, cfg, {"keys": [jwk]}, NONCE, now=NOW)["sub"] == "u1"


def test_alg_none_rejected(rsa_key, cfg):
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(claims()).encode()).rstrip(b"=")
    tok = (hdr + b"." + body + b".").decode()
    assert err(tok, cfg, {"keys": [jwk_of(rsa_key)]}) == "alg_none"


def test_hs256_key_confusion_rejected(rsa_key, cfg):
    # Classic attack: sign with HS256 using the public key as the secret
    tok = jwt.encode(claims(), "secret-that-is-long-enough-for-hmac-sha256", "HS256", {"kid": "k1"})
    assert err(tok, cfg, {"keys": [jwk_of(rsa_key)]}) == "alg_not_allowed"


def test_allowlist_is_configurable(rsa_key):
    c = OidcConfig(ISS, CID, allowed_algs=("ES256",))
    assert err(mint(rsa_key), c, {"keys": [jwk_of(rsa_key)]}) == "alg_not_allowed"


def test_wrong_signature(rsa_key, cfg):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert err(mint(other), cfg, {"keys": [jwk_of(rsa_key)]}) == "bad_signature"


def test_unknown_kid(rsa_key, cfg):
    assert err(mint(rsa_key, kid="zzz"), cfg, {"keys": [jwk_of(rsa_key)]}) == "unknown_kid"


def test_jwk_use_enc_rejected(rsa_key, cfg):
    assert err(mint(rsa_key), cfg, {"keys": [jwk_of(rsa_key, use="enc")]}) == "key_mismatch"


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"iss": "https://evil"}, "issuer_mismatch"),
        ({"aud": "other"}, "audience_mismatch"),
        ({"aud": [CID, "x"]}, "azp_mismatch"),
        ({"exp": NOW - 20}, "expired"),
        ({"exp": None}, "no_exp"),
        ({"nbf": NOW + 100}, "not_yet_valid"),
        ({"iat": NOW + 100}, "iat_in_future"),
        ({"sub": None}, "no_sub"),
        ({"nonce": "other"}, "nonce_mismatch"),
        ({"nonce": None}, "nonce_mismatch"),
    ],
)
def test_claim_failures(rsa_key, cfg, over, code):
    tok = mint(rsa_key, claims(**over))
    assert err(tok, cfg, {"keys": [jwk_of(rsa_key)]}) == code


def test_multi_aud_with_azp_ok(rsa_key, cfg):
    tok = mint(rsa_key, claims(aud=[CID, "x"], azp=CID))
    assert validate_id_token(tok, cfg, {"keys": [jwk_of(rsa_key)]}, NONCE, now=NOW)


def test_leeway(rsa_key, cfg):
    tok = mint(rsa_key, claims(exp=NOW - 5))
    assert validate_id_token(tok, cfg, {"keys": [jwk_of(rsa_key)]}, NONCE, now=NOW)


def test_malformed(cfg):
    assert err("abc", cfg, {"keys": []}) == "malformed"


def test_jwks_client_refreshes_on_rotation(rsa_key, cfg, monkeypatch):
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    docs = [{"keys": [jwk_of(rsa_key)]}, {"keys": [jwk_of(rsa_key), jwk_of(new_key, kid="k2")]}]
    calls = []

    def fetch(_uri):
        calls.append(1)
        return docs[min(len(calls) - 1, 1)]

    client = JwksClient("https://idp.test/jwks", fetch=fetch)
    validate_id_token(mint(rsa_key), cfg, client, NONCE, now=NOW)
    assert len(calls) == 1
    client._loaded = time.time() - 60  # allow a rotation refresh
    validate_id_token(mint(new_key, kid="k2"), cfg, client, NONCE, now=NOW)
    assert len(calls) == 2
