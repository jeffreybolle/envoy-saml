import base64
import hashlib
import urllib.parse
import time

from flask import Flask, request, redirect, make_response
from signxml import XMLVerifier
import yaml

from saml.authn_request import create_authn_request

app = Flask(__name__)

with open('config.yaml', 'r') as stream:
    config = yaml.load(stream)

idp_url = config['idp_url']
issuer = config['issuer']
timeout = config['timeout']
cert = config['certificate']


@app.route('/SAML2/SSO/POST', methods=['POST'])
def process():
    saml_response = request.form['SAMLResponse']
    assertion_data = XMLVerifier().verify(base64.b64decode(saml_response), x509_cert=cert).signed_xml

    if assertion_data.find('{urn:oasis:names:tc:SAML:2.0:assertion}LogoutRequest') is not None:
        response = make_response('You have been logged out')
        response.set_cookie('auth_session', '', expires=0)
        return response

    username = assertion_data.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')\
        .find('{urn:oasis:names:tc:SAML:2.0:assertion}Subject')\
        .find('{urn:oasis:names:tc:SAML:2.0:assertion}NameID').text
    key = 'secret'
    expiry = int(time.time()) + timeout
    signature = hashlib.sha256(f'{username}|{expiry}|{key}'.encode('UTF-8')).hexdigest()
    if 'RelayState' in request.form:
        return_path = request.form['RelayState']
        response = redirect(return_path, 302)
    else:
        response = redirect('/', 302)
    response.set_cookie('auth_session', f'{username}|{expiry}|{signature}')
    return response


@app.route('/SAML2/SSO/LOGIN', methods=['GET'])
def login():
    saml_request = create_authn_request(issuer)
    if 'RelayState' in request.args:
        relay_state = urllib.parse.quote_plus(request.args.get('RelayState').encode('UTF-8'))
        return redirect(f'{idp_url}?SAMLRequest={saml_request}&RelayState={relay_state}')
    else:
        return redirect(f'{idp_url}?SAMLRequest={saml_request}')


@app.route('/SAML2/SSO/LOGOUT', methods=['GET'])
def logout():
    response = make_response('You have been logged out')
    response.set_cookie('auth_session', '', expires=0)
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
