import warnings
from django.conf import settings

autocert_settings_dict = getattr(settings, 'AUTOCERT', {})

LETSENCRYPT_PROD = 'https://acme-v01.api.letsencrypt.org/directory'
LETSENCRYPT_STAGING = 'https://acme-staging.api.letsencrypt.org/directory'
DIRECTORY_URL = autocert_settings_dict.get('DIRECTORY_URL', LETSENCRYPT_PROD)

# 2048 minimum for Let's Encrypt (Boulder)
BITS = autocert_settings_dict.get('BITS', 2048)

ACCOUNT_KEY_PASSWORD = autocert_settings_dict.get('ACCOUNT_KEY_PASSWORD', settings.SECRET_KEY)

OUTPUT_DIR = autocert_settings_dict.get('OUTPUT_DIR')

# Up to 100 per cert https://community.letsencrypt.org/t/rate-limits-for-lets-encrypt/6769
DEFAULT_SUBDOMAINS_TO_REQUEST = autocert_settings_dict.get('DEFAULT_SUBDOMAINS_TO_REQUEST', [])

for old_setting in ['SUBDOMAINS_TO_REQUEST', 'ENV_PREFIX']:
    if autocert_settings_dict.get(old_setting):
        msg = '{} setting deprecated, use DEFAULT_SUBDOMAINS_TO_REQUEST'.format(old_setting)
        warnings.warn(msg, DeprecationWarning)
