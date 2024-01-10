from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('STAGING_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': config('ENGINE'),
        'NAME': config('STAGING_NAME'),
        'USER': config('STAGING_PG_USER'),
        'PASSWORD': config('STAGING_PASSWORD'),
        'HOST': config('STAGING_HOST'),
        'PORT': config('STAGING_PORT')
    }

}

#CORS settings
#currently set to allow all urls
CORS_ORIGIN_ALLOW_ALL = config('STAGING_CORS_ALLOW_ALL', cast=bool)
#change to the following for prod to whitelist only zyllion urls
# CORS_ORIGIN_ALLOW_ALL = False
#
# CORS_ORIGIN_WHITELIST = (
#     'http//:localhost:8000',