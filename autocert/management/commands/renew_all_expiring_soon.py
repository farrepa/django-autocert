import logging

from autocert.models import Certificate
from django.core.management.base import BaseCommand

log = logging.getLogger('command')


class Command(BaseCommand):
    help = 'Renew all autocert Certificates expiring within 30 days'

    def handle(self, *args, **options):
        Certificate.renew_and_write_all_if_expiring_soon()
