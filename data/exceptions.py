from rest_framework.exceptions import APIException
from django.utils.encoding import force_text
from rest_framework import status
from rest_framework.views import exception_handler


class CustomValidation(APIException):
	status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
	default_detail = 'A server error occurred.'

	def __init__(self, detail, field, status_code):
		if status_code is not None:self.status_code = status_code
		if detail is not None:
			self.detail = {field: force_text(detail)}
		else: self.detail = {'detail': force_text(self.default_detail)}


def custom_exception_handler(exc, context):
	response = exception_handler(exc, context)

	if response is not None:
		customized_response = {}
		customized_response['errors'] = []

		for key, value in response.data.items():
			print(key)
			error = {key: value}
			customized_response['errors'].append(error)

		response.data = customized_response

	return response