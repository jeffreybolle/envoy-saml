#!/bin/bash
set -e

python -m saml.generate_config

exec gunicorn --bind 0.0.0.0 --workers 4 saml:app
