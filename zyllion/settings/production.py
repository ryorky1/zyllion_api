from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('PRODUCTION_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

DATABASES = {
    'default': {
        'ENGINE': config('ENGINE'),
        'NAME': config('PRODUCTION_NAME'),
        'USER': config('PRODUCTION_PG_USER'),
        'PASSWORD': config('PRODUCTION_PASSWORD'),
        'HOST': config('PRODUCTION_HOST'),
        'PORT': config('PRODUCTION_PORT')
    }

}

#CORS settings
#currently set to allow all urls
CORS_ORIGIN_ALLOW_ALL = config('PRODUCTION_CORS_ALLOW_ALL', cast=bool)
#change to the following for prod to whitelist only zyllion urls
# CORS_ORIGIN_ALLOW_ALL = False
#
# CORS_ORIGIN_WHITELIST = (
#     'http//:localhost:8000',