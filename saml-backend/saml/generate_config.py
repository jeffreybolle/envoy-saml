import requests
import json
import time
import yaml


def get_access_token():
    response = requests.post('http://idp:8080/auth/realms/master/protocol/openid-connect/token',
                             data={'client_id': 'admin-cli',
                                   'username': 'admin',
                                   'password': 'password',
                                   'grant_type': 'password'})

    response.raise_for_status()
    return response.json()['access_token']


def get_payload():
    with open('platform.json', 'r') as stream:
        return json.loads(stream.read())


def wait_for_idp():
    start = time.time()
    while True:
        if time.time() - start > 120:
            raise Exception('Timeout waiting for the idp server to become available')
        try:
            if requests.get('http://idp:8080/').ok:
                return
        except:
            pass
        time.sleep(2)


def install_client():
    wait_for_idp()
    access_token = get_access_token()

    response = requests.get('http://idp:8080/auth/admin/realms/master/keys',
                            headers={'Authorization': f'bearer {access_token}'},)

    certificate = None
    for key in response.json()['keys']:
        if key['status'] == 'ACTIVE' and key['type'] == 'RSA' and key['algorithm'] == 'RS256':
            certificate = key['certificate']

    if certificate is None:
        raise Exception('Error RSA certificate not found')

    payload = get_payload()
    response = requests.post('http://idp:8080/auth/admin/realms/master/clients',
                             headers={'Authorization': f'bearer {access_token}'},
                             json=payload)

    if response.status_code not in {200, 201, 409}:
        response.raise_for_status()

    return certificate


def generate_config():
    with open('config.yaml', 'r') as stream:
        config = yaml.load(stream)
    if config['certificate'] is None:
        certificate = install_client()
        config['certificate'] = certificate
        with open('config.yaml', 'w') as stream:
            yaml.dump(config, stream)


if __name__ == '__main__':
    generate_config()
