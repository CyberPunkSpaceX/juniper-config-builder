"""SAML 2.0 single sign-on (service provider side).

Works with Microsoft Entra ID, ADFS, Okta, Google Workspace, Authentik,
Keycloak, JumpCloud and other SAML identity providers. Sign-in starts here
(SP-initiated, HTTP-Redirect binding); the provider posts a signed response
back to ``/sso/saml/acs``. The signature is checked with the provider's
certificate (signxml), and only the signed part of the answer is read.

The answer comes back as a cross-site POST, which doesn't carry the session
cookie (SameSite=Lax), so open requests are remembered in the ``saml_requests``
table and each can be used once. Encrypted assertions are not supported: turn
assertion encryption off at the provider (the answer still travels over https).

Settings, group rules and who gets what work as in sso.py.
"""

from __future__ import annotations

import base64
import logging
import re
import secrets
import time
import urllib.parse
import zlib
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, url_for

from . import auth, sso

bp = Blueprint("saml", __name__, template_folder="templates")
log = logging.getLogger("exbuilder.saml")

NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
SKEW = 120  # seconds of clock difference allowed
DEFAULTS = {"enabled": False, "label": "SAML", "idp_entity_id": "", "idp_sso_url": "", "idp_cert": "",
            "username_attr": "", "groups_attr": "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
            "rules": "", "allow_unmapped": False}
sso.DEFAULTS["saml"] = DEFAULTS

SCHEMA = """
CREATE TABLE IF NOT EXISTS saml_requests (
    id TEXT PRIMARY KEY,
    next TEXT,
    until REAL NOT NULL
);
"""


def enabled() -> bool:
    return sso.enabled("saml")


def sp_entity_id() -> str:
    return sso.base_url() + url_for("saml.metadata")


def acs_url() -> str:
    return sso.base_url() + url_for("saml.acs")


def _db():
    auth.db().executescript(SCHEMA)
    return auth.db()


# --------------------------------------------------------------- endpoints
@bp.get("/sso/saml/metadata")
def metadata():
    xml = (f'<?xml version="1.0"?>\n<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
           f'entityID="{escape(sp_entity_id())}">\n  <md:SPSSODescriptor AuthnRequestsSigned="false" '
           f'WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
           f'    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>\n'
           f'    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
           f'Location="{escape(acs_url())}" index="0"/>\n  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n')
    return Response(xml, mimetype="application/samlmetadata+xml")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@bp.get("/sso/saml")
def start():
    cfg = sso.settings("saml")
    if not cfg.get("enabled"):
        abort(404)
    rid = "_" + secrets.token_hex(20)
    db = _db()
    db.execute("DELETE FROM saml_requests WHERE until < ?", (time.time(),))
    nxt = request.args.get("next")
    db.execute("INSERT INTO saml_requests (id, next, until) VALUES (?, ?, ?)",
               (rid, auth._safe_next(nxt) if nxt else None, time.time() + 600))
    db.commit()
    req = (f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{rid}" Version="2.0" '
           f'IssueInstant="{_iso(time.time())}" Destination="{escape(cfg["idp_sso_url"])}" '
           f'AssertionConsumerServiceURL="{escape(acs_url())}" '
           f'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
           f'<saml:Issuer>{escape(sp_entity_id())}</saml:Issuer>'
           f'<samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"/>'
           f'</samlp:AuthnRequest>')
    deflated = zlib.compress(req.encode())[2:-4]  # raw DEFLATE
    query = urllib.parse.urlencode({"SAMLRequest": base64.b64encode(deflated).decode()})
    sep = "&" if "?" in cfg["idp_sso_url"] else "?"
    return redirect(cfg["idp_sso_url"] + sep + query)


def _fail(message: str, detail: str = ""):
    log.warning("SAML sign-in failed: %s %s", message, detail)
    return render_template("auth/login.html", error=message, providers=sso.login_providers()), 403


def _time(value: str | None) -> float | None:
    if not value:
        return None
    value = re.sub(r"\.\d+", "", value.strip()).replace("Z", "+00:00")
    return datetime.fromisoformat(value).timestamp()


def certificates(text: str) -> list[str]:
    """PEM certificates from the settings box (bare base64 from metadata files works too)."""
    found = re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text or "", re.S)
    if not found and (text or "").strip():
        body = re.sub(r"\s+", "", text)
        found = ["-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
                 + "\n-----END CERTIFICATE-----"]
    return found


def verify_response(xml: bytes, cfg: dict, now: float | None = None) -> dict:
    """Check a SAML response. Returns {name_id, attributes, in_response_to} or raises ValueError."""
    from lxml import etree
    from signxml import XMLVerifier

    now = now or time.time()
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_comments=True)
    root = etree.fromstring(xml, parser=parser)
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise ValueError("not a SAML response")
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != "urn:oasis:names:tc:SAML:2.0:status:Success":
        raise ValueError(f"provider said {status.get('Value') if status is not None else 'nothing'}")
    if root.find("saml:EncryptedAssertion", NS) is not None:
        raise ValueError("the assertion is encrypted; turn assertion encryption off at the provider")
    if root.get("Destination") and root.get("Destination") != acs_url():
        raise ValueError(f"response is for {root.get('Destination')}")
    signed = None
    errors = []
    for pem in certificates(cfg.get("idp_cert", "")):
        try:
            signed = XMLVerifier().verify(root, x509_cert=pem).signed_xml
            break
        except Exception as exc:  # wrong certificate or bad signature
            errors.append(str(exc))
    if signed is None:
        raise ValueError("signature check failed: " + ("; ".join(errors) or "no certificate saved"))
    # Read only what the signature covers.
    if signed.tag == f"{{{NS['saml']}}}Assertion":
        assertion = signed
    elif signed.tag == f"{{{NS['samlp']}}}Response":
        found = signed.findall("saml:Assertion", NS)
        if len(found) != 1:
            raise ValueError("expected exactly one assertion")
        assertion = found[0]
    else:
        raise ValueError("the signature covers neither the response nor the assertion")
    issuer = assertion.findtext("saml:Issuer", namespaces=NS)
    if cfg.get("idp_entity_id") and (issuer or "").strip() != cfg["idp_entity_id"].strip():
        raise ValueError(f"assertion is from {issuer}")
    cond = assertion.find("saml:Conditions", NS)
    if cond is not None:
        nb, na = _time(cond.get("NotBefore")), _time(cond.get("NotOnOrAfter"))
        if (nb and now + SKEW < nb) or (na and now - SKEW >= na):
            raise ValueError("assertion is not valid at this time (check the server clocks)")
        audiences = [a.text.strip() for a in cond.findall("saml:AudienceRestriction/saml:Audience", NS) if a.text]
        if audiences and sp_entity_id() not in audiences:
            raise ValueError(f"assertion is for {', '.join(audiences)}, not {sp_entity_id()}")
    subject = assertion.find("saml:Subject", NS)
    name_id = subject.findtext("saml:NameID", namespaces=NS) if subject is not None else None
    in_response_to = None
    ok = False
    for sc in subject.findall("saml:SubjectConfirmation", NS) if subject is not None else []:
        if sc.get("Method") != "urn:oasis:names:tc:SAML:2.0:cm:bearer":
            continue
        data = sc.find("saml:SubjectConfirmationData", NS)
        if data is None:
            continue
        na = _time(data.get("NotOnOrAfter"))
        if data.get("Recipient") == acs_url() and na and now - SKEW < na:
            in_response_to, ok = data.get("InResponseTo"), True
            break
    if not ok:
        raise ValueError(f"no bearer confirmation for {acs_url()}")
    attributes: dict[str, list[str]] = {}
    for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        attributes[attr.get("Name", "")] = [(v.text or "").strip() for v in attr.findall("saml:AttributeValue", NS)]
    return {"name_id": (name_id or "").strip(), "attributes": attributes, "in_response_to": in_response_to}


@bp.post("/sso/saml/acs")
def acs():
    cfg = sso.settings("saml")
    if not cfg.get("enabled"):
        abort(404)
    raw = request.form.get("SAMLResponse", "")
    if not raw or len(raw) > 1_000_000:
        return _fail("No sign-in answer from the identity provider.")
    try:
        result = verify_response(base64.b64decode(raw), cfg)
    except Exception as exc:
        return _fail("The identity provider's answer did not check out.", str(exc)[:500])
    db = _db()
    pending = db.execute("SELECT * FROM saml_requests WHERE id = ? AND until > ?",
                         (result["in_response_to"] or "", time.time())).fetchone()
    if pending is None:
        return _fail("That sign-in expired or was already used. Start again from the sign-in page.")
    db.execute("DELETE FROM saml_requests WHERE id = ?", (pending["id"],))
    db.commit()
    attrs = result["attributes"]
    username = (attrs.get(cfg.get("username_attr") or "") or [result["name_id"]])[0]
    groups = attrs.get(cfg.get("groups_attr") or "", [])
    user = sso.sign_in_external("saml", username, result["name_id"] or username, groups)
    if isinstance(user, str):
        return _fail(user)
    log.info("SAML sign-in of %r", user["username"])
    return auth._finish_login(user, pending["next"])


# ---------------------------------------------------------- settings page
def page_context() -> dict:
    cfg = sso.settings("saml")
    return {"cfg": cfg, "entity_id": sp_entity_id(), "acs": acs_url(), "metadata": sp_entity_id(),
            "certs": len(certificates(cfg.get("idp_cert", "")))}


def handle_settings_form(which: str, me: str) -> bool:
    """The SAML part of the Sign-in settings form. False when the form is not for SAML."""
    if which == "saml_metadata":
        _fill_from_metadata(request.form.get("metadata_xml", ""))
        return True
    if which != "saml":
        return False
    cfg = sso.settings("saml")
    for key, default in DEFAULTS.items():
        if isinstance(default, bool):
            cfg[key] = request.form.get(key) == "1"
        elif key in request.form:
            cfg[key] = request.form[key] if key in ("idp_cert", "rules") else request.form[key].strip()
    _, problems = sso.parse_rules(cfg["rules"])
    if cfg["idp_sso_url"] and not sso._https_ok(cfg["idp_sso_url"]):
        problems.append("The sign-in URL must be an https:// address.")
    if cfg["idp_cert"].strip() and not certificates(cfg["idp_cert"]):
        problems.append("Paste the provider's signing certificate (PEM, BEGIN CERTIFICATE).")
    if cfg["enabled"] and not (cfg["idp_sso_url"] and certificates(cfg["idp_cert"]) and cfg["idp_entity_id"]):
        problems.append("Fill in the provider's entity ID, sign-in URL and certificate before turning SAML on.")
    for p in problems:
        flash(p, "error")
    if not problems:
        sso.save_settings("saml", cfg)
        log.warning("audit: %r changed SAML sign-in settings (enabled=%s)", me, cfg["enabled"])
        flash("SAML settings saved.", "ok")
    return True


def _fill_from_metadata(text: str) -> None:
    """Take the entity ID, sign-in URL and certificate from the provider's metadata XML."""
    from lxml import etree
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    ds = "http://www.w3.org/2000/09/xmldsig#"
    try:
        root = etree.fromstring(text.strip().encode(), parser=etree.XMLParser(resolve_entities=False, no_network=True))
    except Exception:
        flash("That is not valid metadata XML.", "error")
        return
    entity = root if root.tag == f"{{{md}}}EntityDescriptor" else root.find(f".//{{{md}}}EntityDescriptor")
    idp = entity.find(f"{{{md}}}IDPSSODescriptor") if entity is not None else None
    if idp is None:
        flash("No identity provider (IDPSSODescriptor) in that metadata.", "error")
        return
    url = next((s.get("Location") for s in idp.findall(f"{{{md}}}SingleSignOnService")
                if s.get("Binding", "").endswith("HTTP-Redirect")), None)
    certs = []
    for kd in idp.findall(f"{{{md}}}KeyDescriptor"):
        if kd.get("use") in (None, "signing"):
            for c in kd.findall(f".//{{{ds}}}X509Certificate"):
                certs += certificates(c.text or "")
    cfg = sso.settings("saml")
    cfg.update(idp_entity_id=entity.get("entityID", ""), idp_sso_url=url or cfg["idp_sso_url"],
               idp_cert="\n".join(dict.fromkeys(certs)) or cfg["idp_cert"])
    sso.save_settings("saml", cfg)
    flash(f"Read the metadata: {cfg['idp_entity_id']}, {len(certs)} signing certificate(s)."
          + ("" if url else " It has no HTTP-Redirect sign-in URL; fill that in by hand."), "ok")


def init_app(app) -> None:
    app.register_blueprint(bp)
    auth.PUBLIC_ENDPOINTS.update({"saml.start", "saml.acs", "saml.metadata"})
