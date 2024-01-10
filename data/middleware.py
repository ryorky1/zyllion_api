from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
import re
from rest_framework.views import APIView
from .utils import allowed_onboard_req_int
USERS_EXCEEDED_EXEMPT = (
    r'^account/create$',
    r'^plans/list/onboarding$',
    r'^plans/list$',
    r'^user/login$',
    r'^user/login/refresh$',
    r'^user/logout/all$',
    r'^account/detaildata$',
    r'^account/updateall$',
    r'^account/updateplan$',
    r'^account/systems$',
    r'^user/list$',
    r'^user/list/([0-9]+)$',
    r'^user/display/([0-9]+)$',
    r'^user/availablegroups$',
    r'^user/updatestatus$',
    r'^user/availablecompanies$',
    r'^app/account/datacheck$',
)

DEACTIVATED_EXEMPT = (
    r'^plans/list/onboarding$',
    r'^plans/list$',
    r'^user/login$',
    r'^user/login/refresh$',
    r'^user/logout/all$',
    r'^account/detaildata$',
    r'^account/updateplan$',
    r'^account/systems$',
    r'^app/account/datacheck$',
    r'^account/reactivate$',
    r'^account/updatecard$',
    r'^password-reset$',
    r'^password/reset/confirm$',
)


USERS_EXCEEDED_URLS = [re.compile(url) for url in USERS_EXCEEDED_EXEMPT]


DEACTIVATED_EXEMPT_URLS = [re.compile(url) for url in DEACTIVATED_EXEMPT]




class UserLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        view_class = view_func.cls
        try:
            view = view_class()
            view.action_map = {}
            request = view.initialize_request(request)
        except (AttributeError, TypeError):
            request = APIView().initialize_request(request)
        path = request.path_info.lstrip('/')
        response = Response(
            {"detail": "Account has exceeded allowed number of users"},
            content_type="application/json",
            status=status.HTTP_401_UNAUTHORIZED,
        )

        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = "application/json"
        response.renderer_context = {}

        if not any(url.match(path) for url in USERS_EXCEEDED_URLS):
            try:
                if request.user.account.user_set.filter(is_active=True).count() > int(request.user.account.num_users):
                    return response
            except Exception:
                pass


class DeactivatedAccountMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        view_class = view_func.cls
        try:
            view = view_class()
            view.action_map = {}
            request = view.initialize_request(request)
        except (AttributeError, TypeError):
            request = APIView().initialize_request(request)
        path = request.path_info.lstrip('/')
        response = Response(
            {"detail": "Account inactive"},
            content_type="application/json",
            status=status.HTTP_401_UNAUTHORIZED,
        )

        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = "application/json"
        response.renderer_context = {}

        if not any(url.match(path) for url in DEACTIVATED_EXEMPT_URLS):
            try:
                if request.user.account.is_active == False:
                    return response
            except Exception:
                pass