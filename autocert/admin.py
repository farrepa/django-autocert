from django.contrib import admin, messages

from . import models


class AccountAdmin(admin.ModelAdmin):
    list_display = 'name directory_url'.split()
    fieldsets = (
        (None, {
            'fields': ('name',
                       ('is_registered', 'directory_url'))
        }),
        ('CSR Information', {
            'fields': (('country', 'state', 'locality'),
                       ('organization_name', 'organizational_unit_name'),
                       'email_address')
        }),

        ('Timestamps', {
            'fields': ('created', 'modified')
        }),
    )
    readonly_fields = ('is_registered', 'directory_url', 'created', 'modified')


class CertificateAdmin(admin.ModelAdmin):
    list_display = 'site certificate_common_name certificate_expiry_date'.split()
    fieldsets = (
        (None, {
            'fields': [('site', 'account'), 'domains_to_request']
        }),
        ('Artifacts', {
            'fields': ['csr', 'certificate', 'intermediate_certificates'],
            'classes': ['collapse']
        }),
        ('Timestamps', {
            'fields': ['certificate_expiry_date', 'created', 'modified']
        }),
    )
    readonly_fields = ('csr', 'certificate', 'intermediate_certificates', 'certificate_expiry_date',
                       'created', 'modified')
    actions = ['request_and_write_cert']

    def request_and_write_cert(self, request, queryset):
        for cert in queryset.all():
            try:
                cert.request_and_write_cert()
                self.message_user(request, message="Wrote certificate for {}".format(cert.domains_to_request))
            except Exception as e:
                self.message_user(request, message=e, level=messages.ERROR)
    request_and_write_cert.short_description = "Request and write certificate"


admin.site.register(models.Certificate, CertificateAdmin)
admin.site.register(models.Account, AccountAdmin)
