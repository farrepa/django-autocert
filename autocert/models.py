# coding=utf-8
from __future__ import unicode_literals
import logging
import os
from datetime import datetime
from datetime import timedelta
import OpenSSL
from acme import client as acme_client
from acme import errors
from acme import jose
from django.db import models
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from . import settings

log = logging.getLogger(__name__)


class AcmeKeyModel(models.Model):
    key = models.TextField(editable=False)

    class Meta:
        abstract = True

    def get_key(self):
        password = settings.ACCOUNT_KEY_PASSWORD.encode()
        if not self.key:
            self.set_key()
            self.save()
        return serialization.load_pem_private_key(self.key.encode(), password=password, backend=default_backend())

    def set_key(self):
        password = settings.ACCOUNT_KEY_PASSWORD.encode()
        key = rsa.generate_private_key(public_exponent=65537, key_size=settings.BITS, backend=default_backend())
        self.key = key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.TraditionalOpenSSL,
                                     encryption_algorithm=serialization.BestAvailableEncryption(password))

    def set_key_if_blank(self):
        if not self.key:
            self.set_key()

    def get_unencrypted_key(self):
        return self.get_key().private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                            encryption_algorithm=serialization.NoEncryption())


class Account(AcmeKeyModel):
    name = models.CharField(max_length=255, default='New Account')
    directory_url = models.CharField(max_length=255, default=settings.DIRECTORY_URL, editable=False)
    is_registered = models.BooleanField(default=False)
    country = models.CharField(max_length=2, help_text='2 letter country code (ISO 3166-1 alpha-2)')
    state = models.CharField(max_length=64, help_text='state or province name')
    locality = models.CharField(max_length=64, help_text='e.g. city')
    organization_name = models.CharField(max_length=64, help_text='e.g. company name')
    organizational_unit_name = models.CharField(max_length=64, help_text='e.g. section')
    email_address = models.EmailField()
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return u'{}'.format(self.name)

    def get_jwk_key(self):
        return jose.JWKRSA(key=self.get_key())

    def get_client(self):
        client = acme_client.Client(self.directory_url, self.get_jwk_key())
        if not self.is_registered:
            self.register_account(client)
        return client

    def register_account(self, client):
        registration = client.register()
        client.agree_to_tos(registration)
        self.is_registered = True
        self.save()


class Certificate(AcmeKeyModel):
    site = models.OneToOneField('sites.Site', related_name='certificate')
    domain = models.CharField(max_length=255, blank=True)
    domains_to_request = models.TextField(blank=True, help_text='Space separated list of domains to request in cert')
    account = models.ForeignKey(Account)
    csr = models.TextField(blank=True)
    certificate = models.TextField(blank=True)
    intermediate_certificates = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        self.set_csr_if_blank()
        super(Certificate, self).save(*args, **kwargs)
    def get_domain(self):
        return self.domain or u'{}{}'.format(settings.ENV_PREFIX, self.site.domain)

    def get_subdomains(self):
        return [u'{}.{}'.format(subdomain, self.get_domain()) for subdomain in settings.SUBDOMAINS_TO_REQUEST]

    def get_all_domains(self):
        if self.domain and not self.all_domains_to_request:
            self.all_domains_to_request = [self.get_domain()] + self.get_subdomains()
            self.save()
        return self.all_domains_to_request

    def get_san_entries(self):
        return [x509.DNSName(u'{}'.format(san)) for san in self.get_all_domains()]

    def set_csr_if_blank(self):
        if not self.csr:
            private_key = self.get_key()
            builder = x509.CertificateSigningRequestBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, self.get_domain()),
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.account.country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.account.state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.account.locality),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.account.organization_name),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, self.account.organizational_unit_name),
            ]))
            builder = builder.add_extension(x509.SubjectAlternativeName(self.get_san_entries()), critical=False)
            csr = builder.sign(private_key, hashes.SHA256(), default_backend())
            self.csr = csr.public_bytes(serialization.Encoding.PEM)

    def get_wrapped_csr(self):
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, self.csr)
        return jose.util.ComparableX509(csr)

    def request_challenges_and_cert(self):
        client = self.account.get_client()
        authzrs = []
        for domain in self.get_all_domains():
            challenge = Challenge.objects.create(certificate=self, domain=domain)
            authzrs.append(challenge.request_challenge())
        try:
            certr, authzrs = client.poll_and_request_issuance(self.get_wrapped_csr(), authzrs)
        except (errors.Error, errors.PollError) as e:
            raise Exception("Challenge polling or issuance failed: {}".format(self.domain, e))
        else:
            self.fetch_certificate_and_chain(certr)

    def fetch_certificate_and_chain(self, certr):
        client = self.account.get_client()
        self.certificate = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certr.body.wrapped)
        self.save()
        chain = client.fetch_chain(certr)
        self.intermediate_certificates = ''
        for i in chain:
            self.intermediate_certificates += OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, i.wrapped)
        self.save()

    @staticmethod
    def get_crt_path(domain):
        return os.path.join(settings.OUTPUT_DIR, domain + '.crt')

    @staticmethod
    def get_key_path(domain):
        return os.path.join(settings.OUTPUT_DIR, domain + '.key')

    def write_to_disk(self):
        if settings.OUTPUT_DIR:
            for domain in self.get_all_domains():
                with open(self.get_crt_path(domain), 'w') as f:
                    f.write(self.full_certificate)
                with open(self.get_key_path(domain), 'w') as f:
                    f.write(self.get_unencrypted_key().decode())
        else:
            raise Exception('No OUTPUT_DIR specified')

    def certificate_expires_soon(self, days_left=30):
        if not self.expiry_date:
            return False
        return datetime.utcnow() + timedelta(days=days_left) > self.expiry_date

    def renew_and_write_if_expiring_soon(self, days_left=30):
        if self.certificate_expires_soon(days_left=days_left):
            self.request_challenges_and_cert()
            self.write_to_disk()

    @classmethod
    def renew_and_write_all_if_expiring_soon(cls, days_left=30):
        for cert in cls.objects.all():
            cert.renew_and_write_if_expiring_soon(days_left=days_left)

    @property
    def full_certificate(self):
        if self.certificate:
            return '{}{}'.format(self.certificate, self.intermediate_certificates)

    @property
    def expiry_date(self):
        if self.certificate:
            cert = x509.load_pem_x509_certificate(str(self.certificate), default_backend())
            return cert.not_valid_after

    @property
    def primary_domain(self):
        if self.certificate:
            cert = x509.load_pem_x509_certificate(str(self.certificate), default_backend())
            return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


class Challenge(models.Model):
    certificate = models.ForeignKey(Certificate, related_name='challenges')
    domain = models.CharField(max_length=255)
    path = models.CharField(max_length=255)
    validation = models.CharField(max_length=255)
    uri = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        get_latest_by = 'created'

    def request_challenge(self):
        client = self.certificate.account.get_client()
        jwk_key = self.certificate.account.get_jwk_key()
        authzr = client.request_domain_challenges(domain=self.domain)
        http_challenges = [challenge for challenge in authzr.body.challenges if challenge.chall.typ == 'http-01']
        assert len(http_challenges) == 1
        challenge = http_challenges[0]
        self.path = challenge.path
        challenge_data = challenge.to_partial_json()
        self.uri = challenge_data.get('uri')
        self.validation = challenge.chall.validation(jwk_key)
        self.save()
        chall_response = challenge.response(jwk_key)
        client.answer_challenge(challenge, chall_response)
        return authzr
