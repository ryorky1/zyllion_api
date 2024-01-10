import stripe
import os
import re
from decouple import config
from .exceptions import CustomValidation
from .models import Plan
from .utils import creditcardvalidation

if os.environ['DJANGO_SETTINGS_MODULE'] == 'zyllion.settings.production':
	stripe_api_key = config('STRIPE_PROD_API_KEY')
else:
	stripe_api_key = config('STRIPE_DEV_API_KEY')

stripe.api_key = stripe_api_key

def create_subscription(data):
	ccdata = data.get('ccinfo', '')
	creditcardvalidation(ccdata)
	if re.match('^\d{2}\/\d{4}$', ccdata.get('exp_date', '')):
		exp_date = ccdata.get('exp_date').split('/')
	else:
		raise CustomValidation('Date must be in MM/YYYY format', 'error', 400)
	try:
		plan = Plan.objects.get(pk=data.get('plan'))
		cardtoken = stripe.Token.create(
			card={
				"number": ccdata.get('creditcard'),
				"exp_month": exp_date[0],
				"exp_year": exp_date[1],
				"cvc": ccdata.get('cvc'),
				"address_zip": ccdata.get('address_zip')
			},

		)
		customer = stripe.Customer.create(
			description=data.get('company_name', ''),
			email=data.get('email'),
			source=cardtoken.id,

		)
		subscription = stripe.Subscription.create(
			customer=customer.id,
			items=[
				{
					"plan": plan.stripe_plan_id
				}
			]
		)
		return customer.id
	except stripe.error.CardError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.RateLimitError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.InvalidRequestError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.AuthenticationError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.APIConnectionError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.StripeError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except Exception as e:
		raise CustomValidation(e, 'error', 400)


def update_subscription_plan(old_plan, new_plan, customer_token):
	try:
			si = stripe.Subscription.list(
				limit=1,
				customer=customer_token,
				plan=old_plan.stripe_plan_id
			)
			stripe.SubscriptionItem.modify(
				sid=si.data[0]['items'].data[0].id,
				plan=new_plan.stripe_plan_id
			)
	except stripe.error.CardError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.RateLimitError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.InvalidRequestError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.AuthenticationError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.APIConnectionError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.StripeError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except Exception as e:
		raise CustomValidation(e, 'error', 400)


def update_card(request):
	ccdata = request.data.get('ccinfo', '')
	creditcardvalidation(ccdata)
	if re.match('^\d{2}\/\d{4}$', ccdata.get('exp_date', '')):
		exp_date = ccdata.get('exp_date').split('/')
	else:
		raise CustomValidation('Date must be in MM/YYYY format', 'error', 400)
	try:
		cardtoken = stripe.Token.create(
			card={
				"number": ccdata.get('creditcard'),
				"exp_month": exp_date[0],
				"exp_year": exp_date[1],
				"cvc": ccdata.get('cvc'),
				"address_zip": ccdata.get('address_zip')
			},

		)
		new_source = stripe.Customer.create_source(
			request.user.account.stripe_cust_token,
			source=cardtoken.id
		)
		cust_default_src = stripe.Customer.modify(
			request.user.account.stripe_cust_token,
			default_source=new_source.id
		)
		return cust_default_src
	except stripe.error.CardError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.RateLimitError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.InvalidRequestError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.AuthenticationError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.APIConnectionError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.StripeError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except Exception as e:
		raise CustomValidation(e, 'error', 400)

def cancel_subscription(request):
	try:
		subscription = stripe.Subscription.list(
			limit=1,
			customer=request.user.account.stripe_cust_token
		)
		stripe.Subscription.delete(
			subscription.data[0].id,
			prorate=True
		)
		return True
	except stripe.error.RateLimitError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.InvalidRequestError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.AuthenticationError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.APIConnectionError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.StripeError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except Exception as e:
		raise CustomValidation(e, 'error', 400)

def reactivate_subscription(request, data):
	ccdata = data.get('ccinfo', '')
	creditcardvalidation(ccdata)
	if re.match('^\d{2}\/\d{4}$', ccdata.get('exp_date', '')):
		exp_date = ccdata.get('exp_date').split('/')
	else:
		raise CustomValidation('Date must be in MM/YYYY format', 'error', 400)
	try:
		plan = Plan.objects.get(pk=data.get('plan'))
		cardtoken = stripe.Token.create(
			card={
				"number": ccdata.get('creditcard'),
				"exp_month": exp_date[0],
				"exp_year": exp_date[1],
				"cvc": ccdata.get('cvc'),
				"address_zip": ccdata.get('address_zip')
			},

		)
		new_source = stripe.Customer.create_source(
			request.user.account.stripe_cust_token,
			source=cardtoken.id
		)
		stripe.Customer.modify(
			request.user.account.stripe_cust_token,
			default_source=new_source.id
		)
		subscription = stripe.Subscription.create(
			customer=request.user.account.stripe_cust_token,
			items=[
				{
					"plan": plan.stripe_plan_id
				}
			]
		)
		return subscription.id
	except stripe.error.CardError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.RateLimitError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.InvalidRequestError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.AuthenticationError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.APIConnectionError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except stripe.error.StripeError as e:
		raise CustomValidation(e.json_body.get('error', {}).get('message', {}), e.json_body.get('error', {}).get('param', {}),
	                       400)
	except Exception as e:
		raise CustomValidation(e, 'error', 400)