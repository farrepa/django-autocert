import os
from setuptools import setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(name='django-autocert',
      version='0.1.5',
      packages=['autocert'],
      include_package_data=True,
      license='MIT',
      description="Automatic SSL certificates from Let's Encrypt for Django projects",
      long_description=README,
      author='Patrick Farrell',
      author_email='p@farrell.io',
      url='https://github.com/farrepa/django-autocert/',
      keywords='django ssl certificate acme',
      install_requires=['acme>=0.9.3', 'Django>=1.8', 'urllib3', 'josepy'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'Topic :: Software Development :: Build Tools',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
      ],
     )
