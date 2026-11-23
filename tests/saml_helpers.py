"""Test-only IdP: generates a throwaway key and cert and signs SAML responses with signxml."""

import copy
import uuid
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner, methods

from saas_governance_kit.saml.validator import SAML, SAMLP

IDP = "https://idp.test/metadata"
SP = "https://sp.test/metadata"
ACS = "https://sp.test/acs"
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)


class TestIdp:
    __test__ = False

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
        self.cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(FIXED_NOW - timedelta(days=1))
            .not_valid_after(FIXED_NOW + timedelta(days=365))
            .sign(self.key, hashes.SHA256())
        )
        self.cert_pem = self.cert.public_bytes(serialization.Encoding.PEM)
        self.key_pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def build(
        self, *, audience=SP, destination=ACS, in_response_to="req-1", name_id="alice@example.com",
        not_before=FIXED_NOW - timedelta(minutes=1), not_on_or_after=FIXED_NOW + timedelta(minutes=5),
        assertion_id=None, issuer=IDP, attrs=None,
    ) -> etree._Element:  # fmt: skip
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        aid = assertion_id or f"_a{uuid.uuid4().hex}"
        attrs = attrs or {"groups": ["eng", "oncall"]}
        attr_xml = "".join(
            f'<saml:Attribute Name="{k}">'
            + "".join(f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in vs)
            + "</saml:Attribute>"
            for k, vs in attrs.items()
        )
        xml = f"""<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="_r{uuid.uuid4().hex}"
 Version="2.0" IssueInstant="{FIXED_NOW.strftime(fmt)}" Destination="{destination}"
 InResponseTo="{in_response_to}">
<saml:Issuer>{issuer}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{FIXED_NOW.strftime(fmt)}">
<saml:Issuer>{issuer}</saml:Issuer>
<saml:Subject><saml:NameID>{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData Recipient="{ACS}" InResponseTo="{in_response_to}"
 NotOnOrAfter="{not_on_or_after.strftime(fmt)}"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="{not_before.strftime(fmt)}" NotOnOrAfter="{not_on_or_after.strftime(fmt)}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{FIXED_NOW.strftime(fmt)}" SessionIndex="s1"/>
<saml:AttributeStatement>{attr_xml}</saml:AttributeStatement>
</saml:Assertion></samlp:Response>"""
        return etree.fromstring(xml.encode())

    def _signer(self):
        return XMLSigner(
            method=methods.enveloped,
            signature_algorithm="rsa-sha256",
            digest_algorithm="sha256",
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        )

    def sign_assertion(self, response: etree._Element) -> etree._Element:
        response = copy.deepcopy(response)
        assertion = response.find(f"{{{SAML}}}Assertion")
        signed = self._signer().sign(
            assertion, key=self.key_pem, cert=self.cert_pem, reference_uri=assertion.get("ID"),
            id_attribute="ID",
        )  # fmt: skip
        # SAML requires the Signature to follow the Issuer
        sig = signed.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
        signed.remove(sig)
        signed.find(f"{{{SAML}}}Issuer").addnext(sig)
        response.replace(assertion, signed)
        return response

    def sign_response(self, response: etree._Element) -> etree._Element:
        return self._signer().sign(
            copy.deepcopy(response), key=self.key_pem, cert=self.cert_pem,
            reference_uri=response.get("ID"), id_attribute="ID",
        )  # fmt: skip

    @staticmethod
    def to_bytes(el: etree._Element) -> bytes:
        return etree.tostring(el)
