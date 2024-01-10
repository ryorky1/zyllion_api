from django.urls import include, re_path, path
from django.conf.urls import include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    re_path('', include('data.urls')),
]

if settings.DEBUG:
  urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
