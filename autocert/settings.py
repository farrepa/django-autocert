from django.conf import settings

autocert_settings_dict = getattr(settings, 'AUTOCERT', {})

LETSENCRYPT_PROD = 'https://acme.api.letsencrypt.org/directory'
LETSENCRYPT_STAGING = 'https://acme-staging.api.letsencrypt.org/directory'
DIRECTORY_URL = autocert_settings_dict.get('DIRECTORY_URL', LETSENCRYPT_PROD)

# 2048 minimum for Let's Encrypt (Boulder)
BITS = autocert_settings_dict.get('BITS', 2048)

# Up to 100 per cert
# https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769
SUBDOMAINS_TO_REQUEST = autocert_settings_dict.get('SUBDOMAINS_TO_REQUEST', [])

# e.g. 'staging.'
ENV_PREFIX = autocert_settings_dict.get('ENV_PREFIX', '')

ACCOUNT_KEY_PASSWORD = autocert_settings_dict.get('ACCOUNT_KEY_PASSWORD', settings.SECRET_KEY)

OUTPUT_DIR = autocert_settings_dict.get('OUTPUT_DIR')
