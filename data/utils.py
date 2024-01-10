import urllib.parse
from rest_framework.exceptions import PermissionDenied
from decouple import config
from cryptography.fernet import Fernet
f = Fernet(config('CRYPTOKEY'))
from rest_framework_jwt.serializers import VerifyJSONWebTokenSerializer
from django.forms import ValidationError
from .exceptions import CustomValidation
import calendar
from datetime import date, datetime
from django.utils import timezone
#convenience functions


##obfuscators
def number_obfuscator(value):
	if value:
		last4 = str(value)
		return '*****'+last4[-4:]
	else:
		return ""

def email_obfuscator(value):
	if value:
		email_split = value.split('@')
		domain_split = email_split[1].split('.', 1)
		if len(email_split[0]) > 2:
			first2 = email_split[0][:-2] + '***@'
		else:
			first2 = email_split[0]
		if len(domain_split[0]) > 2:
			domain2 = domain_split[0][:-2] + '****.' + domain_split[1]
		else:
			domain2 = domain_split[0]+'.'+domain_split[1]
		return first2+domain2
	else:
		return ""

def urlencode(str):
	return urllib.parse.quote(str)


def urldecode(str):
	return urllib.parse.unquote(str)

def listiteminlist(a, b):
	return not set(a).isdisjoint(b)

def permissioncheck(plan):
	if plan.parent_id != 7:
		raise PermissionDenied

def encryptdict(dict, keys=None):
	for k, v in dict.items():
		if not keys:
			dict[k] = f.encrypt(v.encode()).decode('utf-8')
		else:
			if k in keys:
				dict[k] = f.encrypt(v.encode()).decode('utf-8')
	return dict

def decryptdict(dict, keys=None):
	for k, v in dict.items():
		if not keys:
			dict[k] = f.decrypt(v.encode()).decode('utf-8')
		else:
			if k in keys:
				dict[k] = f.decrypt(v.encode()).decode('utf-8')
	return dict

def get_user_from_jwt(data):
	try:
		valid_data = VerifyJSONWebTokenSerializer().validate(data)
		user = valid_data['user']
		return user
	except ValidationError as v:
		raise CustomValidation("error validating JWT", 'detail', 400)

def is_int(input):
	try:
		num = int(input)
	except ValueError:
		return False
	return True

def allowed_onboard_req_int(val):
	if is_int(val):
		allowed_requests = int(val)
	elif val == 'Unlimited':
		allowed_requests = 1000000
	elif ' / Month' in val:
		ar = val.split(' ')
		allowed_requests = int(ar[0])
	else:
		allowed_requests = 0
	return allowed_requests

def get_month_first_last_day(date=None):
	if date is None:
		date = timezone.now()
	first_day = date.replace(day = 1)
	last_day = date.replace(day = calendar.monthrange(date.year, date.month)[1])
	return first_day, last_day

def creditcardvalidation(data):
	if not data:
		raise CustomValidation('No credit card information provided', 'error', 400)
	req_list = ['creditcard', 'exp_date', 'cvc', 'address_zip']
	cckey_list = list(data.keys())
	missing_cc_fields = [item for item in req_list if item not in cckey_list]
	if missing_cc_fields:
		raise CustomValidation(missing_cc_fields[0] + ' is required', 'error', 400)
	for key, value in data.items():
		if not value:
			raise CustomValidation(key + ' is required', 'error', 400)
