from .base import *

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('TESTING_SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': config('ENGINE'),
        'NAME': config('TESTING_NAME'),
        'USER': config('TESTING_PG_USER'),
        'PASSWORD': config('TESTING_PASSWORD'),
        'HOST': config('TESTING_HOST'),
        'PORT': config('TESTING_PORT')
    }

}

#CORS settings
#currently set to allow all urls
CORS_ORIGIN_ALLOW_ALL = config('TESTING_CORS_ALLOW_ALL', cast=bool)
#change to the following for prod to whitelist only zyllion urls
# CORS_ORIGIN_ALLOW_ALL = False
#
# CORS_ORIGIN_WHITELIST = (
#     'http//:localhost:8000',