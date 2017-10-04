Django Autocert is a Django app to automatically obtain and renew X.509
(i.e. TLS or SSL) certificates from Let's Encrypt or other certificate
authorities that support the `ACME
protocol <https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment>`__.

Requirements
------------

* Django >=1.8 
* ``django.contrib.sites`` in your INSTALLED\_APPS

Installation
------------

#. ``pip install django-autocert``
#. Add ``autocert`` to ``INSTALLED_APPS``
#. Add ``autocert.middleware.AcmeChallengeMiddleware`` to
   ``MIDDLEWARE_CLASSES``, ahead of ``django.middleware.security.SecurityMiddleware`` if it's present.
#. ``./manage.py migrate``

Further Installation Notes
~~~~~~~~~~~~~~~~~~~~~~~~~~

django-autocert requires `cryptography <https://cryptography.io/>`__
which has `platform-specific installation
requirements <https://cryptography.io/en/latest/installation/>`__ for
Linux and macOS:

Debian and Ubuntu
                 

``sudo apt-get install build-essential libssl-dev libffi-dev python-dev``

RHEL/Fedora
           

``sudo yum install gcc libffi-devel python-devel openssl-devel``

macOS
     

``brew install openssl env LDFLAGS="-L$(brew --prefix openssl)/lib" CFLAGS="-I$(brew --prefix openssl)/include" pip install cryptography``

License
-------

django-autocert is MIT licensed

Authors
-------

Patrick Farrell @farrepa on Github and
`Twitter <https://twitter.com/farrepa/>`__
