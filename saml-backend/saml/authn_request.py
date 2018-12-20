import base64
import datetime
import urllib.parse
import zlib
import uuid


def create_authn_request(issuer):
    issue_instance = datetime.datetime.now().replace(tzinfo=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    guid = uuid.uuid4()

    authn_request = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest 
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
  ID="{guid}" Version="2.0" 
  IssueInstant="{issue_instance}" 
  AssertionConsumerServiceIndex="0" 
  AttributeConsumingServiceIndex="0">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:NameIDPolicy AllowCreate="true" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"/>
</samlp:AuthnRequest>'''

    compressor = zlib.compressobj(level=zlib.Z_DEFAULT_COMPRESSION, method=zlib.DEFLATED, wbits=-15)
    compressed_request = compressor.compress(authn_request.encode('UTF-8'))
    compressed_request += compressor.flush()
    return urllib.parse.quote_plus(base64.b64encode(compressed_request).decode('UTF-8'))


