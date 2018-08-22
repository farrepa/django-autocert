import logging

from autocert.models import Certificate
from django.core.management.base import BaseCommand

log = logging.getLogger('command')


class Command(BaseCommand):
    help = 'Write all autocert Certificates to disk'

    def handle(self, *args, **options):
        for cert in Certificate.objects.all():
            cert.write_to_disk()
