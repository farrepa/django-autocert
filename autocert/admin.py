from django.contrib import admin

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
    list_display = 'site primary_domain expiry_date'.split()
    fieldsets = (
        (None, {
            'fields': (('site', 'account', 'primary_domain'),)
        }),
        ('Artifacts', {
            'fields': ('csr', 'certificate', 'intermediate_certificates',)
        }),
        ('Timestamps', {
            'fields': ('expiry_date', 'created', 'modified')
        }),
    )
    readonly_fields = ('csr', 'certificate', 'intermediate_certificates', 'expiry_date',
                       'primary_domain', 'created', 'modified')

admin.site.register(models.Certificate, CertificateAdmin)
admin.site.register(models.Account, AccountAdmin)
