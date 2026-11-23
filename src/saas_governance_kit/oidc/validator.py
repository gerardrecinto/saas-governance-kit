"""OIDC ID token validation per OpenID Connect Core 3.1.3.7 (signature, iss, aud, exp, nonce)."""

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWK

DEFAULT_ALGS = ("RS256", "ES256")
FORBIDDEN_ALGS = {"none", "NONE", "None"}


class IdTokenError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class OidcConfig:
    issuer: str
    client_id: str
    allowed_algs: tuple[str, ...] = DEFAULT_ALGS
    leeway_seconds: int = 60
    max_age_seconds: int | None = None


class JwksClient:
    """Fetch and cache a JWKS. Refreshes once when an unknown kid appears (key rotation)."""

    def __init__(self, jwks_uri: str, ttl: int = 3600, fetch: Callable[[str], dict] | None = None):
        self.jwks_uri = jwks_uri
        self.ttl = ttl
        self._fetch = fetch or self._http_fetch
        self._keys: dict | None = None
        self._loaded = 0.0

    @staticmethod
    def _http_fetch(uri: str) -> dict:
        r = httpx.get(uri, timeout=10)
        r.raise_for_status()
        return r.json()

    def _load(self) -> None:
        self._keys = self._fetch(self.jwks_uri)
        self._loaded = time.time()

    def get(self, kid: str | None) -> dict | None:
        if self._keys is None or time.time() - self._loaded > self.ttl:
            self._load()
        found = _find(self._keys, kid)
        if found is None and time.time() - self._loaded > 30:
            self._load()
            found = _find(self._keys, kid)
        return found


def _find(jwks: dict | None, kid: str | None) -> dict | None:
    keys = (jwks or {}).get("keys", [])
    if kid is None:
        return keys[0] if len(keys) == 1 else None
    return next((k for k in keys if k.get("kid") == kid), None)


def validate_id_token(
    token: str,
    config: OidcConfig,
    jwks: dict | JwksClient,
    expected_nonce: str | None,
    now: float | None = None,
) -> dict[str, Any]:
    now = time.time() if now is None else now
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise IdTokenError("malformed", str(e)) from None
    alg = header.get("alg")
    if alg in FORBIDDEN_ALGS or alg is None:
        raise IdTokenError("alg_none", "Unsigned tokens are rejected")
    if alg not in config.allowed_algs:
        raise IdTokenError("alg_not_allowed", f"alg {alg} not in {config.allowed_algs}")

    kid = header.get("kid")
    jwk = jwks.get(kid) if isinstance(jwks, JwksClient) else _find(jwks, kid)
    if jwk is None:
        raise IdTokenError("unknown_kid", f"No key for kid {kid!r}")
    if jwk.get("use", "sig") != "sig" or jwk.get("alg", alg) != alg:
        raise IdTokenError("key_mismatch", "JWK use or alg does not match the token header")
    expected_kty = {"RS": "RSA", "PS": "RSA", "ES": "EC"}.get(alg[:2])
    if jwk.get("kty") != expected_kty:
        raise IdTokenError("key_mismatch", f"JWK kty {jwk.get('kty')} cannot verify {alg}")

    try:
        key = PyJWK.from_dict({**jwk, "alg": alg}).key
        claims = jwt.decode(
            token,
            key,
            algorithms=[alg],
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
    except jwt.InvalidSignatureError:
        raise IdTokenError("bad_signature", "Signature verification failed") from None
    except jwt.PyJWTError as e:
        raise IdTokenError("malformed", str(e)) from None

    leeway = config.leeway_seconds
    if claims.get("iss") != config.issuer:
        raise IdTokenError("issuer_mismatch", f"iss {claims.get('iss')!r}")
    aud = claims.get("aud")
    auds = [aud] if isinstance(aud, str) else (aud or [])
    if config.client_id not in auds:
        raise IdTokenError("audience_mismatch", f"aud {aud!r}")
    if len(auds) > 1 and claims.get("azp") != config.client_id:
        raise IdTokenError("azp_mismatch", "Multiple audiences require azp to equal client_id")
    exp = claims.get("exp")
    if not isinstance(exp, int | float):
        raise IdTokenError("no_exp", "exp claim is required")
    if now - leeway >= exp:
        raise IdTokenError("expired", f"exp {exp}")
    nbf = claims.get("nbf")
    if nbf is not None and now + leeway < nbf:
        raise IdTokenError("not_yet_valid", f"nbf {nbf}")
    iat = claims.get("iat")
    if not isinstance(iat, int | float):
        raise IdTokenError("no_iat", "iat claim is required")
    if iat > now + leeway:
        raise IdTokenError("iat_in_future", f"iat {iat}")
    if config.max_age_seconds is not None and now - iat > config.max_age_seconds:
        raise IdTokenError("too_old", "Token older than max_age_seconds")
    if not claims.get("sub"):
        raise IdTokenError("no_sub", "sub claim is required")
    if expected_nonce is not None and claims.get("nonce") != expected_nonce:
        raise IdTokenError("nonce_mismatch", "nonce does not match the authentication request")
    return claims
