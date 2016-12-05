import logging
from django.apps import AppConfig

log = logging.getLogger(__name__)


class DjangoAutocertConfig(AppConfig):
    name = 'autocert'
    verbose_name = "Autocert"

    def ready(self):
        # TODO check OUTPUT_DIR is defined
        pass
