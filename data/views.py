from datetime import datetime, timedelta,date, time
from rest_framework import views, permissions, status, mixins, generics, serializers
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
User = get_user_model()
from .serializers import *
from django.contrib.auth.models import Group, Permission
from .models import User, Plan, Account, ContactInfo, PaymentMethod, AccountPlanLog, System, Company, UserLog, \
	CompanyType, VendorApprover
from .utils import urldecode, listiteminlist, permissioncheck, encryptdict, get_user_from_jwt, is_int, \
	allowed_onboard_req_int, get_month_first_last_day
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import NotFound
from .logs import userlogger, accountlogger, invoicelogger
from .permissions import *
from .exceptions import CustomValidation
from django.db.models import Avg, Count, Min, Sum, Q
from collections import OrderedDict
import uuid
from django.template.loader import render_to_string
from subprocess import Popen, PIPE, STDOUT
from django.core import mail
from django.utils.html import strip_tags
import json
from rest_framework_jwt import views as jwt_views
from rest_framework_jwt import serializers
from .stripe_functions import create_subscription, update_subscription_plan, update_card, cancel_subscription, \
	reactivate_subscription


w9_years = ['2017', '2018']
class UserLoginView(jwt_views.ObtainJSONWebToken):

	serializer = UserUpdateSerializer

	def post(self, request, *args, **kwargs):
		response =  super().post(request, *args, **kwargs)
		if response.status_code == status.HTTP_200_OK:
			user = User.objects.get(email=request.data.get('email'))
			w9 = self.w9(user)
			bankinfo = self.bankinfo(user)
			user_count = self.user_limit(user)
			try:
				if type(user_count) != str:
					r  = dict(response.data, ** {'w9_completed':w9, "bank_info_completed":bankinfo, "account_active":user.account.is_active})
				return Response( dict(r, **user_count))
			except Exception as e:
				raise CustomValidation(user_count, 'detail', 400)
		else:
			return Response(response.data)

	def w9(self, user):
		if user.company.first() is None:
			return False
		if user.company.first().taxform_set.last() is None:
			return False
		else:
			return True
		# return w9
	def bankinfo(self, user):
		if user.company.first() is None:
			return False
		if user.company.first().bankinfo.last() is None:
			return False
		else:
			return True
	def user_limit(self, user):
		user_count = user.account.user_set.filter(is_active=True).count()
		allowed_users = user.account.num_users
		return {'active_users': user_count, 'allowed_users': allowed_users}

class UserRefreshTokenView(jwt_views.RefreshJSONWebToken):

	serializer = UserUpdateSerializer

	def post(self, request, *args, **kwargs):
		response = super().post(request, *args, **kwargs)
		if response.status_code == status.HTTP_200_OK:
			user = get_user_from_jwt(self.request.data)
			w9 = self.w9(user)
			bankinfo = self.bankinfo(user)
			user_count = self.user_limit(user)
			try:
				if type(user_count) != str:
					r = dict(response.data, **{'w9_completed': w9, "bank_info_completed": bankinfo, "account_active":user.account.is_active})
				return Response(dict(r, **user_count))
			except Exception as e:
				raise CustomValidation(user_count, 'detail', 400)
		else:
			return Response(response.data)

	def w9(self, user):
		if user.company.first() is None:
			return False
		if user.company.first().taxform_set.last() is None:
			return False
		else:
			return True
		# return w9
	def bankinfo(self, user):
		if user.company.first() is None:
			return False
		if user.company.first().bankinfo.last() is None:
			return False
		else:
			return True
	def user_limit(self, user):
		user_count = user.account.user_set.filter(is_active=True).count()
		allowed_users = user.account.num_users
		return {'active_users': user_count, 'allowed_users': allowed_users}

class AccountUserCreateView(generics.CreateAPIView):
	"""
	Use this endpoint to register new user.
	"""
	serializer_class = AcctRegistrationUserCreateSerializer
	serializer_class_Account = AccountCreateSerializer
	serializer_class_ContactInfo = ContactInfoCreateSerializer
	serializer_class_Email = EmailCreationSerializer
	permission_classes = [permissions.AllowAny]

	def get_object_Plan_Exists(self):
		try:
			return Plan.objects.get(pk=self.request.data.get('plan', 0), is_active=True, is_displayed=True)
		except Plan.DoesNotExist:
			raise CustomValidation('Plan does not exist', 'detail', 400)

	def perform_create(self, serializer):
		#ensure the plan/pricing exists before proceeding
		plan = self.get_object_Plan_Exists()
		num_users = self.request.data.get('num_users') if self.request.data.get('num_users') else self.get_object_Plan_Exists().allowed_users
		data = {}
		admin_group_list = [1, 2]
		self.request.data['contact_name'] = self.request.data.get('first_name', None) + ' ' + self.request.data.get('last_name', None)
		self.request.data['stripe_plan'] = plan.stripe_plan_id
		self.request.data['num_users'] = num_users if is_int(num_users) else 10000
		acctCreateSerializer = self.serializer_class_Account(data=self.request.data)
		continfoSerializer = self.serializer_class_ContactInfo(data=self.request.data)
		userCreateSerializer = self.serializer_class(data = self.request.data)
		if acctCreateSerializer.is_valid(raise_exception=True) and continfoSerializer.is_valid(raise_exception=True)\
				and userCreateSerializer.is_valid(raise_exception=True):
			customer_id = create_subscription(self.request.data)
			email = self.request.data.get('email').lower()
			account = acctCreateSerializer.save(stripe_cust_token=customer_id)
			continfoSerializer.save(account=account, email=email)
			user = serializer.save(account=account, email=email, is_admin=False,is_active=True, groups=admin_group_list)
			emaildata = {"contact_name":account.contact_name, "company_name":account.company_name,
						 "account_email":user.email}
			data['text'] = render_to_string('client_registration.html', emaildata)
			data['type'] = 1
			data['subject'] = 'Registration Confirmation'
			data['from_address'] = 'info@zyllion.co'
			data['to_address'] = user.email
			emailserializer = self.serializer_class_Email(data=data)
			emailserializer.is_valid(raise_exception=True)
			emailserializer.save(account=account)
			#send the client onboard email
			mail.send_mail(data['subject'], strip_tags(data['text']), data['from_address'], [data['to_address']],
						   html_message=data['text'])
			userlogger(self, user, 'create')

class PlanListView(generics.ListAPIView):

	queryset = Plan.objects.filter(is_active=True, is_displayed=True).order_by('id')

	serializer_class = PlanListSerializer
	permission_classes = [permissions.AllowAny]

	def list(self, request, *args, **kwargs):
		if  self.kwargs.get('parentplan'):
			if self.kwargs.get('parentplan').lower() == 'onboarding':
				parentplan = get_object_or_404(Plan, id=7)
				plansdata = self.get_queryset().filter(parent=parentplan.id)
		else:
			plansdata = self.get_queryset().all()

		plans = self.serializer_class(plansdata, many=True)
		return Response(plans.data)

class UserLogoutAllView(views.APIView):
	"""
	Use this endpoint to log out all sessions for a given user.
	"""
	permission_classes = [permissions.IsAuthenticated]

	def post(self, request, *args, **kwargs):
		user = self.request.user
		user.jwt_secret = uuid.uuid4()
		user.save()
		return Response({"success":"User is logged Out"}, status=status.HTTP_204_NO_CONTENT)

class AccountDetailView(generics.ListAPIView):
	serializer_class = AccountDetailSerializer
	serializer_class_Plans = PlanListSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_queryset(self):
		return Account.objects.filter(pk=self.request.user.account.id)

	def get_queryset_Plan(self):
		return Plan.objects.filter(is_active=True, is_displayed=True).order_by('id')

	def list(self, request, *args, **kwargs):
		account = self.serializer_class(self.get_queryset(), many=True)
		plans = self.serializer_class_Plans(self.get_queryset_Plan(), many=True)
		userCount=User.objects.filter(account=self.request.user.account.id, is_active=True).count()
		accountdata = dict(account.data[0], **{"active_users":userCount})
		return Response({"account":accountdata,"plans":plans.data}, status=status.HTTP_200_OK)

class AccountUpdateAllView(generics.UpdateAPIView):
	"""
	Endpoint to update account information
	"""
	serializer_class = AccountUpdateSerializer
	queryset = Account.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.user.account.id)
		return obj

	def get_object__Plan(self):
		obj = get_object_or_404(Plan, id=self.request.data.get('plan', 0), is_active=True, is_displayed=True)
		return obj

	def perform_update(self, serializer):
		plan = self.get_object__Plan()
		num_users = self.request.data.get('num_users') if self.request.data.get('num_users') else plan.allowed_users
		allowed_users = num_users if is_int(num_users) else 10000
		data = self.request.data
		for k, v in data.items():
			if v is not None and k in ['ap_email', 'ar_email']:
				data[k] = v.lower()

		ap_email = self.request.data.get('ap_email', None)
		ar_email = self.request.data.get('ar_email', None)
		acct = serializer.save(ap_email=ap_email, ar_email=ar_email, plan=plan.id, num_users=allowed_users)
		accountlogger(acct, self)

class AccountUpdateInfoView(generics.UpdateAPIView):
	serializer_class = AccountInfoUpdateSerializer
	queryset = Account.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.user.account.id)
		return obj

	def perform_update(self, serializer):

		ap_email = self.request.data.get('ap_email', None)
		ar_email = self.request.data.get('ar_email', None)
		acct = serializer.save(ap_email=ap_email, ar_email=ar_email)
		accountlogger(acct, self)

class AccountUpdatePlanView(generics.UpdateAPIView):
	serializer_class = AccountPlanUpdateSerializer
	queryset = Account.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.user.account.id)
		return obj

	def get_object__Plan(self):
		obj = get_object_or_404(Plan, pk=self.request.data.get('plan', 0), is_active=True, is_displayed=True)
		return obj

	def perform_update(self, serializer):
		current_plan = self.request.user.account.plan
		plan = self.get_object__Plan()
		num_users = self.request.data.get('num_users') if self.request.data.get('num_users') else plan.allowed_users
		allowed_users = num_users if is_int(num_users) else 10000
		acct = serializer.save(plan=plan.id, num_users=allowed_users)
		update_subscription_plan(current_plan, plan, self.request.user.account.stripe_cust_token)
		accountlogger(acct, self)

class EmailCheckView(generics.ListAPIView):
	"""
	Endpoint for basic email checking
	"""
	queryset=User.objects.all()
	permission_classes = [permissions.AllowAny]

	def list(self, request, *args, **kwargs):
		urlemail = urldecode(kwargs['email'])
		exists= self.get_queryset().filter(email=urlemail.lower()).exists()

		return Response({"exists": exists}, status=status.HTTP_200_OK)

class ListSystemView(generics.ListAPIView):
	"""
	Listing Systems View
	"""
	serializer_class = ListSystemSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return System.objects.all()

	def get_queryset_Account(self):
		return Account.objects.all()

	def list(self, request, *args, **kwargs):
		account = get_object_or_404(self.get_queryset_Account(), pk=self.request.user.account.id)
		systems = self.serializer_class(self.get_queryset().filter(plan=account.plan.id), many=True)
		return Response(systems.data, status=status.HTTP_200_OK)

class CompanyCreateView(generics.CreateAPIView):
	"""
	Endpoint to Create a company
	"""
	queryset = Account.objects.all()
	serializer_class = CompanyCreateSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, user__id=self.request.user.id)
		return obj
	def get_object_User(self):
		return User.objects.filter(account=self.request.user.account.id).first()

	def create(self, serializer):
		account=self.get_object()
		self.request.data['contactinfo'][0]['email'] = self.request.data['contactinfo'][0]['email'].lower()
		companySerializer = self.get_serializer(data=self.request.data)
		companySerializer.is_valid(raise_exception=True)
		company = companySerializer.save(account=account)
		initial_user = self.get_object_User()
		initial_user.company.add(company)

		return Response({"company_id":company.id, "company_name":company.company_name})

class CustomerCreateView(generics.CreateAPIView):
	"""
	Endpoint to create a business
	"""
	queryset = Customer.objects.all()
	serializer_class = CustomerCreateSerializer
	permission_classes = [permissions.IsAuthenticated]

	def perform_create(self, serializer):
		try:
			companyid = int(self.request.data['company']) if int(self.request.data['company']) else 0
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		user_companies = [company.id for company in self.request.user.company.all()]
		if companyid not in user_companies:
			raise CustomValidation('Bad Request', 'detail', 400)
		self.request.data['contactinfo'][0]['email'] = self.request.data['contactinfo'][0]['email'].lower()
		custSerializer = self.get_serializer(data=self.request.data)
		custSerializer.is_valid(raise_exception=True)
		customer = custSerializer.save()
		companylink = CompanyLinkSerializer(data=self.request.data)
		if companylink.is_valid(raise_exception=True):
			companylink.save(customer=customer)

class VendorCreateView(generics.CreateAPIView):
	"""
	Endpoint to create a business
	"""
	queryset = Vendor.objects.all()
	serializer_class = VendorCreateSerializer
	permission_classes = [permissions.IsAuthenticated]

	def perform_create(self, serializer):
		try:
			companyid = int(self.request.data['company']) if int(self.request.data['company']) else 0
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		user_companies = [company.id for company in self.request.user.company.all()]
		if companyid not in user_companies:
			raise CustomValidation('Bad Request', 'detail', 400)
		self.request.data['contactinfo'][0]['email'] = self.request.data['contactinfo'][0]['email'].lower()
		vendSerializer = self.get_serializer(data=self.request.data)
		vendSerializer.is_valid(raise_exception=True)
		vendor = vendSerializer.save()
		companylink = CompanyLinkSerializer(data=self.request.data)
		if companylink.is_valid(raise_exception=True):
			companylink.save(vendor=vendor)

class CompanyUpdateView(generics.UpdateAPIView):
	"""
	Endpoint To update Company Information
	"""
	serializer_class = CompanyUpdateSerializer
	queryset = Company.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		companyid = self.request.data['compid'] if self.request.data['compid'] else 0
		obj = get_object_or_404(queryset, pk=companyid, account=self.request.user.account.id)
		return obj

	def perform_update(self, serializer):
		self.get_object()
		serializer.save()

class CustomerUpdateView(generics.UpdateAPIView):
	"""
	Endpoint To update Customer Information
	"""
	serializer_class = CustomerUpdateSerializer
	queryset = Customer.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsARUser]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		customerid = self.request.data['custid'] if self.request.data['custid'] else 0
		custcomplist = [c.id for c in self.request.user.company.all()]
		obj = get_object_or_404(queryset,pk=customerid, customer__company__in=custcomplist)
		return obj

	def perform_update(self, serializer):
		self.get_object()
		serializer.save()

class VendorUpdateView(generics.UpdateAPIView):
	"""
	Endpoint To update Vendor Information
	"""
	serializer_class = VendorUpdateSerializer
	queryset = Vendor.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		vendorid = self.request.data['vendid'] if self.request.data['vendid'] else 0
		custcomplist = [c.id for c in self.request.user.company.all()]
		obj = get_object_or_404(queryset,pk=vendorid, vendor__company__in=custcomplist)
		return obj

	def perform_update(self, serializer):
		self.get_object()
		serializer.save()

class UserCreateView(generics.CreateAPIView):
	"""
	Endpoint to create a user
	"""
	queryset = User.objects.all()
	serializer_class = UserCreateSerializer
	permission_classes = [permissions.IsAuthenticated, IsManager]

	def get_serializer_context(self):
		self.request.data['user_companies'] = [c.id for c in self.request.user.company.all()]
		return {"request": self.request }

	def get_queryset_UserCompanies(self):
		return Company.objects.filter(account=self.request.user.account.id, id__in=self.request.data.get('company'))

	def get_object(self):
		return Account.objects.get(pk=self.request.user.account.id)

	def create(self, serializer):
		user_groups = self.request.data.get('groups', [])
		userSerializer = self.get_serializer(data=self.request.data)
		if userSerializer.is_valid(raise_exception=True):
			curruser_companies = self.get_queryset_UserCompanies()
			companies = [c.id for c in curruser_companies]
			if not companies:
				raise CustomValidation('No Company Provided', 'detail', 400)
			user = userSerializer.save(is_admin=False, is_active=True, groups=user_groups, account=self.get_object())
			for company in curruser_companies:
				user.company.add(company)
			userlogger(self, user, 'create')

			return Response({"id":user.id,
							 "first_name":user.first_name,
							 "last_name":user.last_name,
							 "email":user.email,
							 "company":companies,
							 "account":user.account.id,
							 "groups":user_groups,
							 }, status=status.HTTP_201_CREATED)

class UserUpdateView(generics.UpdateAPIView):
	"""
	Endpoint for Users to update their information
	"""
	queryset = User.objects.all()
	serializer_class = UserUpdateSerializer
	permission_classes = [permissions.IsAuthenticated, IsUser]

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.user.id)
		return obj

	def perform_update(self, serializer):
		useremail = self.request.data.get('email', None)
		if useremail is None:
			user = serializer.save()
		else:
			user = serializer.save(email=useremail.lower())
		userlogger(self, user, 'update')

class UserAdminUpdateView(generics.UpdateAPIView):
	"""
	Endpoint for Admins and Users to update subordinates information
	"""
	queryset = User.objects.all()
	serializer_class = UserAdminUpdateSerializer
	permission_classes = [permissions.IsAuthenticated, IsManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.data['uid'])
		return obj

	def perform_update(self, serializer):
		if self.request.user.id != self.request.data['uid']:
			init_acct_user =  User.objects.filter(account=self.request.user.account.id).first()
			new_roles = []
			roles_available = []
			# company validation
			account_companies = Company.objects.filter(account=self.get_object().account.id, id__in=self.request.data.get('company'))
			companies = [inv.id for inv in account_companies]
			# group validation
			roles = self.request.user.groups.all()
			role_list = [g.id for g in roles]
			if 2 in role_list and self.request.user.id == init_acct_user.id:
				roles_available = [1,2,3,4,5,6]
			if 2 in role_list and self.request.user.id != init_acct_user.id:
				roles_available = [3, 4, 5, 6]
			if 3 in role_list and 5 in role_list:
				roles_available = [4,6]
			if 3 in role_list:
				roles_available = [4]
			if 5 in role_list:
				roles_available = [6]
			for role in self.request.data['groups']:
				if role in roles_available:
					new_roles.append(role)

			user = serializer.save(company=companies, groups=new_roles)
			userlogger(self, user, 'update')
		raise NotFound({"detail": "Bad Request"})

class ChangePasswordView(generics.UpdateAPIView):
	"""
	Endpoint for changing password.
	"""
	serializer_class = ChangePasswordSerializer
	model = User
	permission_classes = [permissions.IsAuthenticated, IsUser]

	def get_object(self, queryset=None):
		obj = self.request.user
		return obj

	def update(self, request, *args, **kwargs):
		self.object = self.get_object()
		serializer = self.get_serializer(data=self.request.data)

		if serializer.is_valid():
			# Check old password
			if not self.object.check_password(serializer.data.get("old_password")):
				return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
			# set_password also hashes the password that the user will get
			self.object.set_password(serializer.data.get("new_password"))
			self.object.save()
			return Response({"message":"Success"}, status=status.HTTP_200_OK)

		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmptyPasswordResetView(APIView):

	def list(self, request):
		return Response('')

class UserStatusUpdateView(generics.UpdateAPIView):
	"""
	Endpoint to Deactivate/Activate a user
	"""
	queryset = User.objects.all()
	serializer_class = UserActivationSerializer
	permission_classes = [permissions.IsAuthenticated, IsManager]

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.data['uid'], account=self.request.user.account.id)
		return obj

	def perform_update(self, serializer):
		user = serializer.save()
		if user.is_active:
			userlogger(self, user, 'activate')
		else:
			userlogger(self, user, 'deactivate')

class ListCompanyUsersView(generics.ListAPIView):
	"""
	Endpoint to display all users an admin/manager can modify/update
	"""
	queryset = User.objects.all()
	serializer_class = UserListSerializer
	permission_classes = [permissions.IsAuthenticated, IsManager]

	def get_queryset(self):
		user = User.objects.get(pk=self.request.user.id)
		curr_user_groups = user.groups.all()
		init_acct_user = User.objects.filter(account=self.request.user.account.id).first()
		user_company = [company.id for company in user.company.all()]

		compid = self.kwargs.get('companyid') if self.kwargs.get('companyid') else None
		curr_role = []

		for groupid in curr_user_groups:
			curr_role.append(groupid.id)
		if 2 in curr_role and self.request.user.id == init_acct_user.id:
			userquery = User.objects.filter(account=self.request.user.account.id).exclude(
				id=self.request.user.id).order_by('last_name', 'first_name').distinct()
		if 2 in curr_role and self.request.user.id != init_acct_user.id:
			userquery = User.objects.filter(account=self.request.user.account.id, company__in=user_company).exclude(
				id=self.request.user.id).exclude(groups__name__in=['Account manager', 'Admin']).order_by('last_name', 'first_name')\
				.distinct()
		if 3 in curr_role and 5 in curr_role:
			userquery = User.objects.filter(account=self.request.user.account.id, company__in=user_company).exclude(
				id=self.request.user.id).exclude(groups__name__in=['Account manager', 'Admin', 'AP manager', 'AR manager'])\
				.order_by('last_name', 'first_name').distinct()
		if 3 in curr_role:
			userquery = User.objects.filter(account=self.request.user.account.id, company__in=user_company).exclude(
				id=self.request.user.id).exclude(groups__name__in=['Account manager', 'Admin', 'AP manager', 'AR manager', 'AR user'])\
				.order_by('last_name', 'first_name').distinct()
		if 5 in curr_role:
			userquery = User.objects.filter(account=self.request.user.account.id, company__in=user_company).exclude(
				id=self.request.user.id).exclude(groups__name__in=['Account manager', 'Admin', 'AP manager', 'AP user', 'AR manager'])\
				.order_by('last_name', 'first_name').distinct()
		if compid is not None:
			userquery = userquery.filter(company=compid)
		return userquery
	def list(self, request, *args, **kwargs):
		user_list = self.serializer_class(self.get_queryset(), many=True)
		return Response({"users":user_list.data}, status=status.HTTP_200_OK)

class DisplayUserView(generics.RetrieveAPIView):
	"""
	Endpoint for users to display their own user information and admins to view a users information
	(i.e. firstrname, lastname, email address, etc)
	"""
	queryset = User.objects.all()
	serializer_class = UserListSerializer
	permission_classes = [permissions.IsAuthenticated, IsUser]

	def get_object(self):
		userid = self.kwargs.get('userid') if self.kwargs.get('userid') else None
		if userid is not None:
			user = User.objects.get(pk=self.request.user.id)
			curr_user_groups = user.groups.all()
			init_acct_user = User.objects.filter(account=self.request.user.account.id).first()
			user_company = [company.id for company in user.company.all()]
			curr_role = []

			for groupid in curr_user_groups:
				curr_role.append(groupid.id)
			if 2 in curr_role and self.request.user.id == init_acct_user.id:
				obj = get_object_or_404(self.get_queryset(), pk=userid, account=self.request.user.account.id)
			if 2 in curr_role and self.request.user.id != init_acct_user.id:
				user_queryset = self.get_queryset().filter(company__in=user_company)\
					.exclude(groups__name__in=['Account manager', 'Admin']).distinct()
				obj = get_object_or_404(user_queryset, pk=userid, account=self.request.user.account.id)
			if 3 in curr_role and 5 in curr_role:
				user_queryset = self.get_queryset().filter(company__in=user_company)\
					.exclude(groups__name__in=['Account manager', 'Admin', 'AP manager', 'AR manager']).distinct()
				obj = get_object_or_404(user_queryset, pk=userid, account=self.request.user.account.id)
			if 3 in curr_role:
				user_queryset = self.get_queryset().filter(company__in=user_company)\
					.exclude(groups__name__in=['Account manager', 'Admin', 'AP manager', 'AR manager', 'AR user']).distinct()
				obj = get_object_or_404(user_queryset, pk=userid, account=self.request.user.account.id)
			if 5 in curr_role:
				user_queryset = self.get_queryset().filter(company__in=user_company)\
					.exclude(groups__name__in=['Account manager', 'Admin', 'AP manager', 'AP user', 'AR manager']).distinct()
				obj = get_object_or_404(user_queryset, pk=userid, account=self.request.user.account.id)
			if 4 in curr_role or 6 in curr_role:
				user_queryset = User.objects.none()
				obj = get_object_or_404(user_queryset, pk=userid)
		else:
			obj = get_object_or_404(self.get_queryset(), pk=self.request.user.id)
		return obj

class ListAvailableUserGroupsView(generics.ListAPIView):
	"""
	Endpoint to list all available groups a person can be added to when creating or updating based off on logged in user permission
	"""
	queryset = Group.objects.all()
	serializer_class = GroupSerializer
	permission_classes = [permissions.IsAuthenticated, IsManager]


	def get_queryset(self):
		curr_user_group = User.objects.get(pk=self.request.user.id).groups.all()
		init_acct_user = User.objects.filter(account=self.request.user.account.id).first()
		curr_role = []
		if self.request.user.account.plan.parent_id != 7:
			for groupid in curr_user_group:
				curr_role.append(groupid.id)
			if 2 in curr_role and self.request.user.id == init_acct_user.id:
				return Group.objects.all()
			if 2 in curr_role:
				return Group.objects.exclude(name__in=['Account manager', 'Admin']).order_by('id')
			if 3 in curr_role and 5 in curr_role:
				return Group.objects.exclude(name__in=['Account manager', 'Admin', 'AP manager', 'AR manager']).order_by('id')
			if 3 in curr_role:
				return Group.objects.exclude(name__in=['Account manager', 'Admin', 'AP manager', 'AR manager', 'AR user']).order_by('id')
			if 5 in curr_role:
				return Group.objects.exclude(name__in=['Account manager', 'Admin', 'AP manager', 'AP user', 'AR manager']).order_by('id')
		else:
			for groupid in curr_user_group:
				curr_role.append(groupid.id)
			if 2 in curr_role and self.request.user.id == init_acct_user.id:
				return Group.objects.filter(name__in=['Account manager', 'Admin', 'Onboard user']).order_by('id')
			if 2 in curr_role:
				return Group.objects.filter(name__in=['Onboard user'])

	def list(self, request, *args, **kwargs):
		available_groups = self.serializer_class(self.get_queryset(), many=True)
		return Response(available_groups.data, status=status.HTTP_200_OK)

class ListAvailableCompaniesView(generics.ListAPIView):
	"""
	list all available companies a user can be added to when creating or updating
	"""
	queryset = User.objects.all()
	serializer_class = AvaliableCompaniesSerializer
	permission_classes = [permissions.IsAuthenticated, IsManager]

	def get_queryset(self):
		user = User.objects.get(pk=self.request.user.id).company.all().order_by ('company_name')
		return user

	def list(self, request):
			available_companies = self.serializer_class(self.get_queryset(), many=True)
			return Response({"available_companies":available_companies.data}, status=status.HTTP_200_OK)

##add validation to ensure that the current company isn't both the vendor and buyer and that the other company id is in their network
class CreateInvoiceView(generics.CreateAPIView):
	"""
	Endpoint to Create an invoice
	"""
	queryset = Account.objects.all()
	serializer_class = InvoiceCreateSerializer
	permission_class  = [permissions.IsAuthenticated, IsAPUser]

	def get_object_Companylink(self):
		clqueryset = CompanyLink.objects.filter(company=self.request.data.get('company'))
		if self.request.data['linked_company']:
			clqueryset = clqueryset.filter(linked_company=self.request.data['linked_company'])
		else:
			clqueryset = clqueryset.filter(vendor=self.request.data['vendor'])
		obj = get_object_or_404(clqueryset)
		return obj
	def get_object_Status(self):
		obj = Status.objects.get(pk=5)
		return obj
	def perform_create(self, serializer):

		usercompanylist = [comp.id for comp in self.request.user.company.all()]
		if self.request.data.get('company') not in usercompanylist:
			raise NotFound({"detail": "Bad Request"})
		companylink = self.get_object_Companylink()
		status = self.get_object_Status()
		invoiceSerializer = self.get_serializer(data=self.request.data)
		invoiceSerializer.is_valid(raise_exception=True)
		newinvoice = invoiceSerializer.save(companylink=companylink, status=status)

		##log invoice creation
		invoicelogger(self, newinvoice, 'Received')

class ListInvoicesView(generics.ListAPIView):
	"""
	Endpoint to List all Invoices for a company
	"""
	permission_classes = [permissions.IsAuthenticated, IsAPUser]
	def get_serializer_class(self):
		type = self.kwargs.get('type') if self.kwargs.get('type') else None
		if type == '1':
			return APInvoiceListSerializer
		return ARInvoiceListSerializer

	def get_queryset(self):
		type = self.kwargs.get('type') if self.kwargs.get('type') else None
		companyid = int(self.kwargs.get('companyid')) if self.kwargs.get('companyid') else None
		overdue = self.kwargs.get('overdue') if self.kwargs.get('overdue') else None
		if type == '1':
			queryset = Invoice.objects.filter(buyer=self.request.user.company.id).order_by('-created_date')
			if companyid:
				queryset = queryset.filter(vendor=companyid)
			if overdue:
				if overdue == 'all':
					queryset = queryset.exclude(status__status__in=['paid'])
				elif overdue in ['0', '30', '60', '90']:
					begin_date = ''
					end_date = ''
					overdue_status = overdue_switch(overdue)
					if overdue_status and isinstance(overdue_status, list):
						begin_date = date.today() + timedelta(days=overdue_status[0])
						try:
							end_date = date.today() + timedelta(days=overdue_status[1])
						except IndexError:
							end_date = date.today() + timedelta(days=5475) #equals 15 years
					queryset = queryset.filter(due_date__range=(begin_date, end_date)).exclude(status__status__in=['paid'])
				else:
					queryset = Invoice.objects.none()
		if type == '2':
			queryset = Invoice.objects.filter(vendor=self.request.user.company.id).order_by('-created_date')
			if companyid:
				queryset = queryset.filter(buyer=companyid)
			if overdue:
				if overdue == 'all':
					queryset = queryset.exclude(status__status__in=['paid'])
				elif overdue in ['0', '30', '60', '90']:
					begin_date = ''
					end_date = ''
					overdue_status = overdue_switch(overdue)
					if overdue_status and isinstance(overdue_status, list):
						begin_date = date.today() + timedelta(days=overdue_status[0])
						try:
							end_date = date.today() + timedelta(days=overdue_status[1])
						except IndexError:
							end_date = date.today() + timedelta(days=5475)  # equals 15 years
					queryset = queryset.filter(due_date__range=(begin_date, end_date)).exclude(status__status__in=['paid'])
				else:
					queryset = Invoice.objects.none()

		return queryset

	def list(self, request, *args, **kwargs):
		invoices = self.get_serializer(self.get_queryset(), many=True)
		return Response({"incoices": invoices.data}, status=status.HTTP_200_OK)

class DetailInvoiceView(generics.ListAPIView):
	"""
	Endpoint to display Invoice and Invoice Line data
	"""
	serializer_class = DefaultInvoiceListSerializer
	serializer_class_InvoiceLines = InvoiceLineListSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self):
		return Invoice.objects.filter(pk=self.kwargs.get('invoiceid'), buyer=self.request.user.company.id) | \
			   Invoice.objects.filter(pk=self.kwargs.get('invoiceid'), vendor=self.request.user.company.id)

	def get_queryset_InvoiceLines(self, invoiceid):
		return InvoiceLine.objects.filter(invoice__id=invoiceid)

	def list(self, request, *args, **kwargs):
		invoice = self.get_serializer(self.get_queryset(), many=True)
		invoicelines = self.serializer_class_InvoiceLines(self.get_queryset_InvoiceLines(invoice.data[0]['id']), many=True)
		return Response({"incoice": invoice.data, "invoiceline":invoicelines.data}, status=status.HTTP_200_OK)
##validate/add a decorator to make sure that only a user with the correct id can update
class UpdateInvoiceView(generics.UpdateAPIView):
	"""
	Update an Invoice and InvoiceList
	"""
	serializer_class = InvoiceUpdateSerializer
	queryset = Invoice.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=self.request.data['id'])
		return obj

	def perform_update(self, serializer):
		invoiceobj = self.get_object()
		invoice = serializer.save()
		invoicelogger(self, invoice, 'Updated')

#add correct validations for update function currently just using placeholders
class DeleteInvoiceView(generics.UpdateAPIView):
	"""
	Delete an Invoice
	"""
	permission_classes = [permissions.IsAuthenticated, IsAPUser]
	get_queryset = Invoice.objects.all()
	get_queryset_InvoiceLines = InvoiceLine.objects.all()
	def get_serializer_class(self):
		if self.request.data['type'] == "invoice":
			return DefaultInvoiceListSerializer
		return InvoiceLineListSerializer

	def update(self, request, *args, **kwargs):
		invoices=None
		if isinstance(self.request.data['id'], list):
			idlist = self.request.data['id']
		elif isinstance(self.request.data['id'], int):
			idlist = [self.request.data['id']]
		else:

			raise serializers.ValidationError({"detail":"Invalid values passed"})

		if request.data["type"] == "invoice":
			msg = "Invoice"
			invoices = self.get_queryset.filter(pk__in=idlist, vendor=self.request.user.company.id)
			for status in invoices:
				if status.status.status != 'Received':
					raise serializers.ValidationError({"detail": msg+" cannot be deleted"})
			invoice_ids = [inv.id for inv in invoices]
			invoice_lines = self.get_queryset_InvoiceLines.filter(invoice__id__in=invoice_ids)
			success = invoices.update(is_deleted=True)
			invoice_lines.update(is_deleted=True)

		elif request.data["type"] == "line":
			msg = "Invoice Line(s)"
			invoice_lines = self.get_queryset_InvoiceLines.filter(pk__in=idlist, invoice__vendor_id=self.request.user.company.id)
			for line in invoice_lines:
				if line.invoice.status.status != 'Received':
					raise serializers.ValidationError({"detail": msg+" cannot be deleted"})
			success = invoice_lines.update(is_deleted=True)
		else:
			raise NotFound({"detail":"Invalid values passed"})


		if success:
			if invoices:
				invoicelogger(self, invoices.first(), 'Deleted')
			else:
				invoicelogger(self, invoice_lines.first().invoice, 'Deleted')
			return Response({"message": msg+" Deleted"})
		return Response({"detail":"Deletion Error"})

class ChooseCompanyView(generics.ListAPIView):
	"""
	list all available companies a user can be added to when creating or updating
	"""
	queryset = User.objects.all()
	serializer_class = ChooseCompaniesSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		user = User.objects.get(pk=self.request.user.id).company.all().order_by('company_name')
		return user

	def list(self, request):
			available_companies = self.serializer_class(self.get_queryset(), many=True)
			return Response({"company":available_companies.data}, status=status.HTTP_200_OK)

class AppMenuBarDataView(generics.ListAPIView):
	"""
	Pull all required Information for the App MenuBar
	"""
	serializer_class = AppMenuBarUserSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return User.objects.filter(pk=self.request.user.id)

	def list(self, request, *args, **kwargs):
		user = self.get_queryset()
		userdata = self.serializer_class(user, many=True)
		groups = userdata.data[0].pop('groups')
		usergroupids = [group['id'] for group in groups]
		types = []
		if self.request.user.account.plan.parent_id == 7:
				types.append({"id":3, "type":"onboarding"})
		else:
			if (self.request.user.account.plan.id == 3 and listiteminlist(usergroupids, [2, 3, 4])):
				types.append({"id":1, "type":"ap"})
			if (self.request.user.account.plan.id == 4 and listiteminlist(usergroupids, [2, 5, 6])):
				types.append({"id":2, "type":"ar"})
			if self.request.user.account.plan.id not in [3, 4, 7]:
				if listiteminlist(usergroupids, [2, 3, 4]):
					types.append({"id": 1, "type": "ap"})
				if listiteminlist(usergroupids, [2, 5, 6]):
					types.append({"id": 2, "type": "ar"})
				else:
					types.append({})

		companylist = [{"id":company.id, "company_name":company.company_name} for company in user[0].company.all().order_by('id')]

		return Response({"user":userdata.data, "types":types, "groups":groups, "company":companylist, "system":[{self.request.user.account.system.id, self.request.user.account.system.name}]}, status=status.HTTP_200_OK)

class SetupRequiredView(generics.ListAPIView):
	"""
		Determine if a User needs to go through setup before accessing the site.
	"""
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Account.objects.get(pk=self.request.user.account.id)

	def list(self, request, *args, **kwargs):
		account = self.get_queryset()
		planid = self.request.user.account.plan.id
		if planid in [3]:
			plan_type = [{"ap_email":True}, {"ar_email":False}]
			iscompleted = False if account.ap_email is None else True
		elif planid in [4]:
			plan_type = [{"ap_email": False}, {"ar_email": True}]
			iscompleted = False if account.ar_email is None else True
		elif planid in [7]:
			plan_type = [{"ap_email": False}, {"ar_email": False}]
			iscompleted = True
		else:
			plan_type = [{"ap_email": True}, {"ar_email": True}]
			iscompleted = False if account.ap_email is None  and account.ar_email is None else True
		return Response({"setup_completed":iscompleted, "email_types_required":plan_type})

class CompanySetupStatusView(generics.ListAPIView):
	"""
		Determine if a company has added their W-9 and bankinformation.
	"""
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_queryset_Taxform(self, company):
		return TaxForm.objects.filter(company=company)

	def get_queryset_BankInformation(self, company):
		return BankInformation.objects.filter(company=company)

	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.kwargs.get('companyid', 0))
		if company not in compids or company == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			w9 = True if self.get_queryset_Taxform(company) else False
			bankinfo = True if self.get_queryset_BankInformation(company) else False

		return Response({"w9_completed":w9, "bankinfo_completed":bankinfo}, status=status.HTTP_200_OK)

class SetupCompanyListView(generics.ListAPIView):
	"""
	Lists all Companies Imported into the system that they need to set up information for(will be used across all of setup)
	"""
	serializer_class = SetupCompanyListSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_queryset(self):
		return Company.objects.filter(account=self.request.user.account.id).order_by('company_name')

	def list(self, request, *args, **kwargs):
		company_list= self.serializer_class(self.get_queryset(), many=True)
		return Response(company_list.data, status=status.HTTP_200_OK)

class SetupCreateBankView(generics.CreateAPIView):
	"""
	Create a bank acct entry for a Company in setup
	"""
	queryset = User.objects.all()
	serializer_class = SetupBankCreateSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_object(self):
		return User.objects.get(pk=self.request.user.id)


	def create(self, request, *args, **kwargs):
		user_companies = [company.id for company in self.get_object().company.all()]
		if self.request.data.get('company') not in user_companies:
			raise CustomValidation('Bad Request', 'detail', 400)
		else:
			self.request.data['acctinfo'] = encryptdict(self.request.data.get('bank'), ['routing_num', 'account_num'])
			self.request.data.pop('bank')
			bankInfoSerializer = self.get_serializer(data=self.request.data)
			bankInfoSerializer.is_valid(raise_exception=True)
			bankinfo = bankInfoSerializer.save()
		return Response({"company_id":self.request.data.get('company'), "id": bankinfo.id}, status=status.HTTP_200_OK)

class SetupUpdateBankView(generics.UpdateAPIView):
	"""
	Update a bank account entry in Setup that has already been created
	"""
	queryset = BankInformation.objects.all()
	serializer_class = SetupBankUpdateSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]
	def get_object(self):
		bankid = self.request.data.get('bid', 0)
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset, pk=bankid, company__account=self.request.user.account.id)
		return obj

	def perform_update(self, serializer):
		self.get_object()
		serializer.save()

class SetupListBankView(generics.ListAPIView):
	"""
	List all bank accounts for a company
	"""
	queryset = BankInformation.objects.all()
	serializer_class = SetupBankListSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_queryset(self):
		companyid = self.kwargs.get('company', 0)
		return BankInformation.objects.filter(company=companyid, company__account=self.request.user.account.id)
	def list(self, request, *args, **kwargs):
		bank_list = self.serializer_class(self.get_queryset(), many=True)
		return Response(bank_list.data, status=status.HTTP_200_OK)

class SetupUploadw9View(generics.CreateAPIView):
	"""
	Upload/Update(overwrite) a w-9 pdf for a company into an s3 bucket from Setup ************come back to
	"""
	queryset = TaxForm.objects.all()
	serializer_class = SetupTaxFormSaveSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object_Company(self, companyid):
		return Company.objects.get(pk=companyid)

	def get_object_User(self):
		return User.objects.get(pk=self.request.user.id)

	def create(self, request, *args, **kwargs):
		companyid = int(request.data.get('company', 0))
		user_companies = [company.id for company in self.get_object_User().company.all()]
		if companyid in user_companies:
			taxdata = self.request.data.get('w9')
			for k, v in taxdata.items():
				if k in ['tax_class', 'exemption', 'tin']:
					self.request.data[k] = json.loads(v)
				else:
					self.request.data[k] = v
			self.request.data.pop('w9')
			self.request.data['year'] = w9_years[-1]
			w9form = self.get_serializer(data=self.request.data)
			w9form.is_valid(raise_exception=True)
			w9form.save()
			return Response({"company_id":companyid,"tax_id":w9form.data['id']}, status=status.HTTP_201_CREATED)
		else:
			raise CustomValidation('Bad Request', 'company', 400)

class SetupDisplayw9View(generics.RetrieveAPIView):
	"""
	Display w-9 entry information in Setup
	"""
	serializer_class = SetupTaxFormRetrieveSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_object_User(self):
		return User.objects.get(pk=self.request.user.id)

	def get_object(self):
		cid = self.kwargs.get('cid', 0)
		companyid = int(cid)
		user_companies = [company.id for company in self.get_object_User().company.all()]
		if companyid not in user_companies:
			companyid = 0

		obj = get_object_or_404(TaxForm, company=companyid, is_deleted=False)
		return obj

class SetupApArEmailCheck(generics.ListAPIView):
	"""
	Check if AP or AR emails already exist in the database
	"""
	queryset = Account.objects.all()
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def list(self, request, *args, **kwargs):
		urlemail = urldecode(self.kwargs['aparemail'])
		exists= self.get_queryset().filter(ap_email=urlemail).exists() | self.get_queryset().filter(ar_email=urlemail).exists()

		return Response({"exists": exists}, status=status.HTTP_200_OK)

class SetupCreateEmails(generics.UpdateAPIView):
	"""
	Creates the ap and/or ar zyllion email addresses
	"""
	queryset = Account.objects.all()
	serializer_class = SetupEmailCreateSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		obj = get_object_or_404(self.get_queryset(), pk=self.request.user.account.id)
		return obj

	def perform_update(self, serializer):
		data = self.request.data
		for k, v in data.items():
			if v is not None:
				data[k] = v.lower()

		ap_email = self.request.data.get('ap_email', None)
		ar_email = self.request.data.get('ar_email', None)
		serializer.save(ap_email=ap_email, ar_email=ar_email)

class SetupSaveSystemsView(generics.UpdateAPIView):
	"""
	Saves the system to be synced to
	"""
	queryset = Account.objects.all()
	serializer_class = SetupSystemSaveSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_object(self):
		obj = get_object_or_404(self.get_queryset(), pk=self.request.user.account.id)
		return obj
	def perform_update(self, serializer):
		serializer.save()
#update queryset once we allow linking.  Really think through this!!!
class APUserManagerInvoiceChart(generics.ListAPIView):
	"""
	Displays the data for overdue invoives chart plus additional one for viewing all overdue invoices
	"""
	serializer_class = APOverdueStatusSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self, company, role):
		excludedstatus = ['Paid']
		return Invoice.objects.filter(companylink__company=company).exclude(status__status__in=excludedstatus)

	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		overduedict = {"current":0, "1-30":0, "31-60":0, "61-90":0, "90":0, "alloverdue":0}
		today = date.today()
		thirty = date.today() - timedelta(days=30)
		sixty = date.today() - timedelta(days=60)
		ninty = date.today() - timedelta(days=90)
		company = int(self.kwargs.get('company', 0))
		compids = [comp.id for comp in self.request.user.company.all()]

		role = self.kwargs.get('role', None)
		if self.request.user.account.plan.id == 4 or company not in compids or company  == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			overdue_invoice_chart = self.get_queryset(company, role)
			for invoice in overdue_invoice_chart:
				if (invoice.due_date >= today):
					overduedict['current'] += 1
				if (invoice.due_date < today and invoice.due_date >= thirty):
					overduedict['1-30'] += 1
				if (invoice.due_date < thirty and invoice.due_date >= sixty):
					overduedict['31-60'] += 1
				if (invoice.due_date < sixty and invoice.due_date >= ninty):
					overduedict['61-90'] += 1
				if (invoice.due_date < ninty):
					overduedict['90'] += 1
				if (invoice.due_date < today):
					overduedict['alloverdue'] += 1

		return Response(overduedict, status=status.HTTP_200_OK)

class APManagerOpenInvoiceChart(generics.ListAPIView):
	"""
	Breaks down all open invoices by type
	"""
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.kwargs.get('company', 0))
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			open_invoices_by_type = Invoice.objects.manager_open_invoices_type(company)

		return Response(open_invoices_by_type, status=status.HTTP_200_OK)

class APUnpaidStatusListView(generics.ListAPIView):
	"""
	Lists the Invoice Statuses for the User/Manager Dashboard Unpaid Sidebar Dropdown Filter
	"""

	serializer_class = APInvoiceStatusesSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Status.objects.all().filter(type="AP").exclude(status="Paid").order_by('-id')
	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		statuslist = (self.serializer_class(self.get_queryset(), many=True))
		basestatuslist = statuslist.data
		d2 = OrderedDict([('id', 0), ('status_text', 'All')])
		basestatuslist.append(d2)
		statuslist = list(reversed(basestatuslist))

		return Response(statuslist, status=status.HTTP_200_OK)

class APInvoiceStatusListView(generics.ListAPIView):
	"""
	Lists the Invoices Statuses for the Invoice Page Status Dropdown Filter
	"""

	serializer_class = APInvoiceStatusesSerializer
	permission_classes = [permissions.IsAuthenticated]

	def get_queryset(self):
		return Status.objects.all().filter(type="AP").order_by('-id')
	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		statuslist = (self.serializer_class(self.get_queryset(), many=True))
		basestatuslist = statuslist.data
		d2 = OrderedDict([('id', 0), ('status_text', 'All')])
		basestatuslist.append(d2)
		statuslist = list(reversed(basestatuslist))

		return Response(statuslist, status=status.HTTP_200_OK)

class APUserManagerOpenInvoicesSidebarView(generics.ListAPIView):
	"""
	Displays the Open Invoices for the User/Manager Dashboard
	"""

	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self, company, invstatus):
		if invstatus:
			return Invoice.objects.filter(companylink__company=company, is_deleted=False, status=invstatus) \
					   .exclude(status__status="Paid").order_by('-created_date')
		return Invoice.objects.filter(companylink__company=company, is_deleted=False) \
				   .exclude(status__status="Paid").order_by('-created_date', 'id')
	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.kwargs.get('company', 0))
		invoicelist = []
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			# pagination info
			try:
				pageparam = int(self.request.GET.get('page', 1))
			except ValueError:
				raise CustomValidation('Bad Request', 'detail', 400)
			page = int(pageparam) if pageparam > 0 else 1
			perpage = 250
			offset = (page - 1) * perpage
			limit = offset + perpage
			# end pagination info
			try:
				invstatus = int(self.request.GET.get('status', 5)) if self.request.GET.get('status') else None
			except ValueError:
				raise CustomValidation('Bad Request', 'detail', 400)
			invoices = self.get_queryset(company, invstatus)[offset:limit]
			for inv in invoices:
				vendor_name = inv.companylink.linked_company.company_name if inv.companylink.linked_company \
				and inv.companylink.linked_company.account.is_active == True else inv.companylink.vendor.company_name

				invoicelist.append(
					{
						"id": inv.id,
						"invoice_num":inv.invoice_num,
						"vendor_name":vendor_name,
						"amount":"{0:.2f}".format(inv.total),
						"due_date":inv.due_date.strftime("%m-%d-%Y"),
						"status": inv.status.status_text
					}
				)
			return Response({"invoice_list": invoicelist}, status=status.HTTP_200_OK)

class APUserManagerPaidInvoicesSidebarView(generics.ListAPIView):
	"""
	Display paid invoices in dashboard side menubar
	"""

	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self, company):
		return Invoice.objects.filter(companylink__company=company, is_deleted=False, status__status="Paid") \
		.order_by('-created_date')

	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.kwargs.get('company', 0))
		invoicelist = []
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			# pagination info
			try:
				pageparam = int(self.request.GET.get('page', 1))
			except ValueError:
				raise CustomValidation('Bad Request', 'detail', 400)
			page = int(pageparam) if pageparam > 0 else 1
			perpage = 250
			offset = (page - 1) * perpage
			limit = offset + perpage
			# end pagination info
			invoices = self.get_queryset(company)[offset:limit]

			for inv in invoices:
				vendor_name = inv.companylink.linked_company.company_name if inv.companylink.linked_company \
				and inv.companylink.linked_company.account.is_active == True else inv.companylink.vendor.company_name
				invoicelist.append(
					{
						"id": inv.id,
						"invoice_num":inv.invoice_num,
						"vendor_name":vendor_name,
						"amount":"{0:.2f}".format(inv.total),
						"due_date":inv.due_date.strftime("%m-%d-%Y"),
						"status": inv.status.status_text
					}
				)
			return Response({"invoice_list": invoicelist}, status=status.HTTP_200_OK)
#Add number of required approvers
class APUserManagerInvoicesPageView(generics.ListAPIView):
	"""
	List all invoices, can filter by status, overdue, and search field, is paginated by 100 records
	"""
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self, company, overdue, status, search):
		invoice_queryset = Invoice.objects.filter(companylink__company=company, is_deleted=False).order_by('-created_date')
		today = date.today()
		thirty = date.today() - timedelta(days=30)
		sixty = date.today() - timedelta(days=60)
		ninty = date.today() - timedelta(days=90)
		if overdue:
				if overdue == 'current':
					invoice_queryset = invoice_queryset.filter(due_date__gte= today)
				if overdue == '1-30':
					invoice_queryset = invoice_queryset.filter(due_date__range=(thirty - timedelta(days=1), today))
				if overdue == '31-60':
					invoice_queryset = invoice_queryset.filter(due_date__range=(sixty - timedelta(days=1), thirty))
				if overdue == '61-90':
					invoice_queryset = invoice_queryset.filter(due_date__range=(ninty - timedelta(days=1), sixty))
				if overdue == '90':
					invoice_queryset = invoice_queryset.filter(due_date__lt=ninty)
				if overdue == 'alloverdue':
					invoice_queryset = invoice_queryset.filter(due_date__lt=today)
		if status:
			invoice_queryset = invoice_queryset.filter(status=status)
		if search:
			invoice_queryset = invoice_queryset.filter(
				Q(invoice_num__icontains=search) |
				Q(total__icontains=search) |
				Q(companylink__vendor__company_name__icontains=search) |
				Q(companylink__linked_company__company_name__icontains=search) |
				Q(created_date__icontains=search) |
				Q(due_date__icontains=search)
			).distinct()

		return invoice_queryset
	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.kwargs.get('company', 0))
		overdue = self.request.GET.get('overdue')
		search = self.request.GET.get('search')
		try:
			status = int(self.request.GET.get('status', 1)) if self.request.GET.get('status') else None
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		# pagination info
		try:
			pageparam = int(self.request.GET.get('page', 1))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		page = int(pageparam) if pageparam > 0 else 1
		perpage = 250
		offset = (page-1)*perpage
		limit = offset + perpage
		# end pagination info
		invoicelist = []
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			invoices = self.get_queryset(company, overdue, status, search)[offset:limit]
			for inv in invoices:
				if inv.companylink.linked_company and inv.companylink.linked_company.account.is_active == True:
					invoicelist.append({
						"id": inv.id,
						"company": inv.companylink.linked_company.id,
						"vendor_name": inv.companylink.linked_company.company_name,
						"amount": "{0:.2f}".format(inv.total),
						"due_date": inv.created_date.strftime("%m-%d-%Y"),
						"notes": inv.note_set.count(),
						"approval_count": inv.approver_set.count(),
						"approver_names": [approver.approver.first_name + " " + approver.approver.last_name for approver
										   in inv.approver_set.filter(is_approved=True)],
						"status": inv.status.status_text,
						"document_count": 1
					})
				else:
					invoicelist.append({
						"id":inv.id,
						"vendor":inv.companylink.vendor.id,
						"vendor_name":inv.companylink.vendor.company_name,
						"amount": "{0:.2f}".format(inv.total),
						"due_date":inv.created_date.strftime("%m-%d-%Y"),
						"notes":inv.note_set.count(),
						"approval_count":inv.approver_set.count(),
						"approver_names":[approver.approver.first_name + " " + approver.approver.last_name for approver in inv.approver_set.filter(is_approved=True)],
						"status":inv.status.status_text,
						"document_count":1
					})
		return Response({"invoice_list": invoicelist})

class APVendorListPageView(generics.ListAPIView):
	"""
	Listing of all of a companies associated Vendors
	"""
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self, company, search):
		queryset = CompanyLink.objects.filter(company=company, vendor__isnull=False)
		if search:
			queryset = queryset.filter(
				Q(linked_company__company_name__icontains=search) |
				(Q(vendor__company_name__icontains=search) & Q(linked_company__isnull=True)) |
				Q(linked_company__contactinfo__address1__icontains=search) |
				(Q(vendor__contactinfo__address1__icontains=search) & Q(linked_company__isnull=True)) |
				Q(linked_company__contactinfo__city__icontains=search) |
				(Q(vendor__contactinfo__city__icontains=search) & Q(linked_company__isnull=True)) |
				Q(linked_company__contactinfo__state__icontains=search) |
				(Q(vendor__contactinfo__state__icontains=search) & Q(linked_company__isnull=True)) |
				Q(linked_company__contactinfo__zip__icontains=search) |
				(Q(vendor__contactinfo__zip__icontains=search) & Q(linked_company__isnull=True)) |
				Q(linked_company__contactinfo__email__icontains=search) |
				(Q(vendor__contactinfo__email__icontains=search) & Q(linked_company__isnull=True)) |
				Q(linked_company__contactinfo__phone__icontains=search) |
				(Q(vendor__contactinfo__phone__icontains=search) & Q(linked_company__isnull=True))
			).distinct()
		return queryset

	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.kwargs.get('company', 0))
		vendorlist = []
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			return Response({"detail":"You do not have access to this information"}, status=status.HTTP_400_BAD_REQUEST)
		else:
			# pagination info
			pageparam = int(self.request.GET.get('page', 1))
			page = int(pageparam) if pageparam > 0 else 1
			perpage = 250
			offset = (page-1)*perpage
			limit = offset + perpage
			# end pagination info
			search = self.request.GET.get('search')
			company = int(self.kwargs.get('company', 0))
			companylink = self.get_queryset(company, search)[offset:limit]
			for vend in companylink:
				if vend.linked_company and vend.linked_company.account.is_active == True:
					vendorlist.append({
						"company":vend.linked_company.id,
						"company_name":vend.linked_company.company_name,
						"address":vend.linked_company.contactinfo.get().address1,
						"city":vend.linked_company.contactinfo.get().city,
						"state":vend.linked_company.contactinfo.get().state,
						"zip":vend.linked_company.contactinfo.get().zip,
						"email":vend.linked_company.contactinfo.get().email,
						"phone":vend.linked_company.contactinfo.get().phone,
						"linked":True
					})
				else:
					vendorlist.append({
						"vendor":vend.vendor.id,
						"company_name":vend.vendor.company_name,
						"address":vend.vendor.contactinfo.get().address1,
						"city":vend.vendor.contactinfo.get().city,
						"state":vend.vendor.contactinfo.get().state,
						"zip":vend.vendor.contactinfo.get().zip,
						"email":vend.vendor.contactinfo.get().email,
						"phone":vend.vendor.contactinfo.get().phone,
						"linked":False
					})
			vendorlist = sorted(vendorlist, key=lambda k: k['company_name'])
		return Response({"vendor_list":vendorlist}, status=status.HTTP_200_OK)

class APCompanySettingsListView(generics.ListAPIView):
	"""
	List Company Settings data
	"""
	queryset = Company.objects.all()
	serializer_class = APCompanyInfoSettingsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_queryset(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			company = 0
		queryset = Company.objects.filter(pk=company)

		return queryset

class APCreateBankAccountView(generics.CreateAPIView):
	"""
	Create a Bank Account for a Company
	"""
	serializer_class = APCompanyAddBankAccountSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_queryset(self, company):
		return BankInformation.objects.filter(company=company)
	def perform_create(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		if self.request.data.get('is_default', 0) == 1:
			self.get_queryset(company).update(is_default=0)
		serializer.save()

class APSetDefaultBankAccountView(generics.UpdateAPIView):
	"""
	Set a default Bank Account for a Company
	"""
	serializer_class = APCompanySetDefaultSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_queryset(self):
		return BankInformation.objects.filter(company=int(self.request.data.get('company', 0)))
	def get_object(self):
		queryset = self.get_queryset()
		obj =  get_object_or_404(queryset, pk=int(self.request.data.get('id', 0)))
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		self.get_queryset().update(is_default=0)
		serializer.save(is_default=1)

class APDeleteBankAccountView(generics.UpdateAPIView):
	"""
	Delete a Bank Account for a Company
	"""
	queryset = BankInformation.objects.all()
	serializer_class = APCompanyDeleteBankAccountSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object(self):
		queryset = self.get_queryset()
		obj =  get_object_or_404(queryset, pk=int(self.request.data.get('id', 0)), company=int(self.request.data.get('company', 0)))
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		serializer.save(is_deleted=1)

class APApproverEmailsView(generics.ListAPIView):
	"""
	List of available Users who can Approve an Invoice
	"""
	queryset = User.objects.all()
	serializer_class = APApproverListSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_queryset(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		complist = []
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		complist.append(company)
		queryset = User.objects.filter(company__in=complist).exclude(groups__name__in=["AR manager", "AR user", "AP user"])
		return queryset


class APCreateVendorBankAccountView(generics.CreateAPIView):
	"""
	Create a Bank Account for a vendor
	"""
	serializer_class = APCompanyAddBankAccountSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object(self, company, vendor):
		return CompanyLink.objects.get(company=company, vendor=vendor)

	def get_queryset(self, companylink):
		return BankInformation.objects.filter(companylink=companylink)

	def perform_create(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		companylink = self.get_object(company, vendor)
		if self.request.data.get('is_default', 0) == 1:
			self.get_queryset(companylink).update(is_default=0)
		serializer.save(company=None, companylink=companylink)

class APSetDefaultVendorBankAccountView(generics.UpdateAPIView):
	"""
	Set a default Bank Account for a Vendor
	"""
	serializer_class = APCompanySetDefaultSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_queryset(self):
		return BankInformation.objects.filter(companylink=self.get_object_CompanyLink().id)
	def get_object_CompanyLink(self):
		return CompanyLink.objects.get(company=int(self.request.data.get('company', 0)), vendor=int(self.request.data.get('vendor', 0)))

	def get_object(self):
		obj = get_object_or_404(self.get_queryset(), pk=int(self.request.data.get('id', 0)))
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		self.get_queryset().update(is_default=0)
		serializer.save(is_default=1)

class APDeleteVendorBankAccountView(generics.UpdateAPIView):
	"""
	Delete a Bank Account for a Vendor
	"""
	queryset = BankInformation.objects.all()
	serializer_class = APCompanyDeleteBankAccountSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_CompanyLink(self):
		return CompanyLink.objects.get(company=int(self.request.data.get('company', 0)), vendor=int(self.request.data.get('vendor', 0)))

	def get_object(self):
		obj =  get_object_or_404(self.get_queryset(), pk=int(self.request.data.get('id', 0)), companylink=self.get_object_CompanyLink().id)
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		serializer.save(is_deleted=1)

class APListVendorBankAccountView(generics.ListAPIView):

	serializer_class = ListVendorBankAcctInfoSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_CompanyLink(self, company, vendor):
		return CompanyLink.objects.get(company=company, vendor=vendor)
	def get_queryset(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		return BankInformation.objects.filter(companylink=self.get_object_CompanyLink(company, vendor), is_deleted=False).order_by('-is_default', '-id')

class APCreateVendorPaymentPreferencesView(generics.CreateAPIView):
	"""
	Create Vendor Payment Preferences
	"""
	queryset = PaymentPreference.objects.all()
	serializer_class = CreateVendorPaymentPreferencesSerializer
	permission_class  = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Companylink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def create(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		companylink = self.get_object_Companylink(company, vendor)
		serializer = self.get_serializer(data=self.request.data)
		serializer.is_valid(raise_exception=True)
		instance = serializer.save(companylink=companylink, company=None)
		returndata = ListVendorPaymentPreferencesSerializer(instance)
		return Response(returndata.data, status=status.HTTP_200_OK)

class APUpdateVendorPaymentPreferencesView(generics.UpdateAPIView):
		"""
		Update Vendor Payment Preferences
		"""
		queryset = PaymentPreference.objects.all()
		serializer_class = UpdateVendorPaymentPreferencesSerializer
		permission_classes = [permissions.IsAuthenticated, IsAPManager]

		def get_serializer_context(self):
			return {"request": self.request}
		def get_object_Company(self, company, vendor):
			return get_object_or_404(CompanyLink, company=company, vendor=vendor)
		def get_object(self):
			compids = [comp.id for comp in self.request.user.company.all()]
			try:
				ppid = int(self.request.data.get('id', 0))
			except ValueError:
				raise CustomValidation('Bad Request', 'detail', 400)
			try:
				company = int(self.request.data.get('company', 0))
			except ValueError:
				raise CustomValidation('Bad Request', 'detail', 400)
			try:
				vendor = int(self.request.data.get('vendor', 0))
			except ValueError:
				raise CustomValidation('Bad Request', 'detail', 400)
			if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
				raise CustomValidation('Bad Request', 'detail', 400)
			obj = PaymentPreference.objects.get(pk=ppid, companylink=self.get_object_Company(company, vendor).id)
			return obj

		def perform_update(self, serializer):
			permissioncheck(self.request.user.account.plan)
			self.get_object()
			serializer.save()

class APRetrieveVendorPaymentPreferencesView(generics.RetrieveAPIView):
	"""
	List Vendor Payment Preferences
	"""
	queryset = PaymentPreference.objects.all()
	serializer_class = ListVendorPaymentPreferencesSerializer
	serializer_class_Types = ListAllTypesSerializer
	serializer_class_BankInformation = ListBankAcctsSerializer
	serializer_class_PaymentMethods = ListPaymentMethodsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]
	def get_object_CompanyLink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_queryset_Types(self):
		return VendorType.objects.all().order_by('id')
	def get_queryset_CompanyBankInformation(self, company):
		return BankInformation.objects.filter(company=company, is_deleted=False).order_by('-is_default', '-id')
	def get_queryset_VendorBankInformation(self, companylink):
		return BankInformation.objects.filter(companylink=companylink, is_deleted=False).order_by('-is_default', '-id')
	def get_queryset_PaymentMethods(self):
		return PaymentMethod.objects.all().order_by('id')
	def get_object(self):
		return get_object_or_404(self.get_queryset(), companylink=self.get_object_CompanyLink(int(self.kwargs.get('company', 0)), int(self.kwargs.get('vendor', 0))))

	def retrieve(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)


		paymentpreferences = self.serializer_class(self.get_object())
		type_list = self.serializer_class_Types(self.get_queryset_Types(), many=True)
		company_bank_list = self.serializer_class_BankInformation(
			self.get_queryset_CompanyBankInformation(company=company), many=True)
		vendor_bank_list = self.serializer_class_BankInformation(
			self.get_queryset_VendorBankInformation(companylink=self.get_object_CompanyLink(company, vendor)), many=True)
		payment_method_list = self.serializer_class_PaymentMethods(self.get_queryset_PaymentMethods(), many=True)
		rd = {}
		rd.update(paymentpreferences.data)
		rd.update({"type_list":type_list.data, "comp_bank_list":company_bank_list.data, "vend_bank_list":vendor_bank_list.data, "payment_method_list":payment_method_list.data})
		rd.update(rd)
		return Response(rd, status=status.HTTP_200_OK)


class APSaveVendorDefaultApproversView(generics.CreateAPIView):
	"""
	Create/Update Default Approvers(tiers) for a vendor
	"""
	serializer_class = SaveVendorApproversSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Companylink(self):
		return get_object_or_404(CompanyLink, company=int(self.request.data.get('company', 0)), vendor=int(self.request.data.get('vendor', 0)))

	def create(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		company = int(self.request.data.get('company', 0))
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		companylink = self.get_object_Companylink()
		serializer = self.get_serializer(data=self.request.data['vendorapprover'], many=True)
		serializer.is_valid(raise_exception=True)
		serializer.save(companylink=companylink, company=company)
		return Response(serializer.data, status=status.HTTP_200_OK)

class APDeleteVendorDefaultApproversView(generics.UpdateAPIView):
	"""
	Delete Default Approvers(tiers) for a Vendor
	"""
	queryset = VendorApprover.objects.all()
	serializer_class = DeleteVendorApproverSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_CompanyLink(self):
		return CompanyLink.objects.get(company=int(self.request.data.get('company', 0)), vendor=int(self.request.data.get('vendor', 0)))

	def get_object(self):
		obj = get_object_or_404(self.get_queryset(), pk=int(self.request.data.get('id', 0)), companylink=self.get_object_CompanyLink().id)
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		serializer.save(is_deleted=1)

class APListVendorDefaultApproversView(generics.ListAPIView):
	"""
	List Default Approvers(tiers) for a Vendor
	"""

	serializer_class = ListVendorApproverSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_CompanyLink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)
	def get_queryset(self, company, vendor):
		return VendorApprover.objects.filter(companylink=self.get_object_CompanyLink(company, vendor), is_deleted=0)
	def list(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		valist = []
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		vendorapprovers = self.serializer_class(self.get_queryset(company, vendor), many=True)
		for i, ad in enumerate(ad for ad in vendorapprovers.data):
			vaobj = {"id":ad['id'], "above_amount":ad['above_amount'],"user":[]}
			for uc, user in enumerate(ad['user']):
				vaobj["user"].append({"id": user['id'], "name": user['first_name'] + user['last_name'], "email": user['email']})
			valist.append(vaobj)
		return Response(valist, status=status.HTTP_200_OK)


class APCreateVendorInvoivePreferencesView(generics.CreateAPIView):
	"""
	Create Vendor Invoice Preferences
	"""
	serializer_class = CreateVendorInvoiceSettingsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Companylink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def perform_create(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		companylink = self.get_object_Companylink(company, vendor)
		serializer.save(companylink=companylink)

class APUpdateVendorInvoivePreferencesView(generics.UpdateAPIView):
	"""
	Update Vendor Invoice Preferences
	"""
	serializer_class = UpdateVendorInvoiceSettingsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Companylink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_object(self):
		id = int(self.request.data.get('id'))
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		obj = get_object_or_404(InvoicePreference, pk=id, companylink=self.get_object_Companylink(company, vendor))
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		serializer.save()

class APListVendorInvoivePreferencesView(generics.RetrieveAPIView):
	"""
	List Vendor Invoice Preferences
	"""
	serializer_class = ListVendorInvoiceSettingsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_CompanyLink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_object(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		return get_object_or_404(InvoicePreference, companylink=self.get_object_CompanyLink(company, vendor))

class APListVendorRecentInvoicesView(generics.ListAPIView):
	"""
	List Recent Invoices from a Vendor
	"""
	serializer_class=ListVendorInvoicesSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_object_CompanyLink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_queryset(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		return Invoice.objects.filter(companylink=self.get_object_CompanyLink(company, vendor)).exclude(status__status="Paid")[:15]

class APListVendorRecentPaymentsView(generics.ListAPIView):
	"""
	List Recent Payments to a Vendor
	"""
	serializer_class = ListVendorPaymentsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_object_CompanyLink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_queryset(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		return Payment.objects.filter(companylink=self.get_object_CompanyLink(company, vendor),
			invoice__status__status__in=["Partial Payment", "Paid"]).order_by("date_to_pay", "date_payed")[:15]

class APCreateVendorNoteView(generics.CreateAPIView):
	"""
	Create a Note for a Vendor
	"""
	serializer_class = CreateVendorNoteSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_object_Companylink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def perform_create(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		companylink = self.get_object_Companylink(company, vendor)
		serializer.save(companylink=companylink, user=self.request.user)

class APDeleteVendorNoteView(generics.UpdateAPIView):
	"""
	Delete a Note for a Vendoe
	"""
	serializer_class = DeleteVendorNoteSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_object_Companylink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_object(self):
		obj =  get_object_or_404(Note, pk=int(self.request.data.get('id', 0)), companylink=self.get_object_Companylink(
			int(self.request.data.get('company', 0)), int(self.request.data.get('vendor', 0))))
		return obj

	def perform_update(self, serializer):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.request.data.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		serializer.save(is_deleted=True)

class APListVendorNotesView(generics.ListAPIView):
	"""
	List Notes for a vendor
	"""
	serializer_class = ListVendorNotesSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPUser]

	def get_object_CompanyLink(self, company, vendor):
		return get_object_or_404(CompanyLink, company=company, vendor=vendor)

	def get_queryset(self):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.kwargs.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			vendor = int(self.kwargs.get('vendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		return Note.objects.filter(companylink=self.get_object_CompanyLink(company, vendor))

class UtilityImportAccountView(generics.CreateAPIView):
	"""
	Utility Function to import/save GL Accounts for a Company in Quickbooks
	"""
	serializer_class = UtilityCreateCompanyAccountsSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Company(self, company):
		return get_object_or_404(Company, company=company)

	def create(self, request, *args, **kwargs):
		permissioncheck(self.request.user.account.plan)
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		data = self.request.data['QueryResponse']['Account']
		datalist = []
		name_map = {"Name": "name", "Id":"sys_account_id", "Classification":"classification", "Active":"is_active",
					"CurrencyRef":"currency", "CurrentBalance":"balance",
					"CurrentBalanceWithSubAccounts":"balancewithsubs", "AccountType":"type",
					"AccountSubType":"sub_type", "ParentRef":"parent_account", "SyncToken":"synctoken", "AcctNum":"account_num"}
		for row in data:
			datalist.append({name_map[name]: val for name, val in row.items()
							 if name in ["Name", "Id", "Classification", "Active", "CurrencyRef", "CurrentBalance",
										 "CurrentBalanceWithSubAccounts", "AccountType", "AccountSubType", "ParentRef", "SyncToken", "AcctNum"]})
		for dictrow in datalist:
			for k, v in dictrow.items():
				if k == "currency":
					dictrow[k] = dictrow[k]["value"]
				if k == "parent_account":
					dictrow[k] = int(dictrow[k]["value"])
		company = self.get_object_Company(company)
		serializer = self.get_serializer(data=datalist, many=True)
		serializer.is_valid(raise_exception=True)
		try:
			serializer.save(company=company)
		except IntegrityError:
			raise CustomValidation('Bad Request:account already exist', 'detail', 400)

		return Response({"detail":"Success"})

class UtilityImportClassView(generics.CreateAPIView):

	serializer_class = UtilityCreateClassSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Company(self, company):
		return get_object_or_404(Company, company=company)

	def create(self, request, *args, **kwargs):
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		data=self.request.data['QueryResponse']['Class']
		datalist = []
		name_map = {"Id":"sys_class_id", "SyncToken":"synctoken", "Name":"name", "ParentRef":"parent_class", "Active":"is_active"}

		for row in data:
			datalist.append({name_map[name]: val for name, val in row.items()
							 if name in ["Id", "SyncToken", "Name", "ParentRef", "Active"]})

		for dictrow in datalist:
			for k, v in dictrow.items():
				if k == "parent_class":
					dictrow[k] = int(dictrow[k]["value"])

		serializer = self.get_serializer(data=datalist, many=True)
		serializer.is_valid(raise_exception=True)
		try:
			serializer.save(company=self.get_object_Company(company))
		except IntegrityError:
			raise CustomValidation('Bad Request:class already exist', 'detail', 400)

		return Response({"detail":"Success"})

class UtilityImportDepartmentView(generics.CreateAPIView):

	serializer_class = UtilityCreateDepartmentSerializer
	permission_classes = [permissions.IsAuthenticated, IsAPManager]

	def get_object_Company(self, company):
		return get_object_or_404(Company, company=company)

	def create(self, request, *args, **kwargs):
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		data=self.request.data['QueryResponse']['Department']
		datalist = []
		name_map = {"Id":"sys_department_id", "SyncToken":"synctoken", "Name":"name", "ParentRef":"parent_department", "Active":"is_active"}

		for row in data:
			datalist.append({name_map[name]: val for name, val in row.items()
							 if name in ["Id", "SyncToken", "Name", "ParentRef", "Active"]})

		for dictrow in datalist:
			for k, v in dictrow.items():
				if k == "parent_department":
					dictrow[k] = int(dictrow[k]["value"])

		serializer = self.get_serializer(data=datalist, many=True)
		serializer.is_valid(raise_exception=True)
		try:
			serializer.save(company=self.get_object_Company(company))
		except IntegrityError:
			raise CustomValidation('Bad Request:department already exist', 'detail', 400)

		return Response({"detail":"Success"})

class CreateVendorOnboardEmailView(generics.CreateAPIView):

	queryset = Token.objects.all()
	serializer_class = CreateVendorTokenSerializer
	serializer_class_Email = EmailCreationSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_object(self, company):
		return Company.objects.get(pk=company)

	def get_queryset__AcctOnboardRequests(self):
		dates = get_month_first_last_day()
		return Token.objects.filter(company__account=self.request.user.account.id, date_created__range=(dates[0], dates[1]), is_deleted=False).count()

	def create(self, request, *args, **kwargs):
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.get_queryset__AcctOnboardRequests() > allowed_onboard_req_int(self.request.user.account.plan.allowed_onboard_requests):
			raise CustomValidation('Account has exceeded allowed number of onboard requests', 'detail', 400)
		data = self.request.data
		token = str(uuid.uuid4())
		data['token'] = token
		tokenserializer = self.get_serializer(data=data)
		tokenserializer.is_valid(raise_exception=True)
		onboarddata = tokenserializer.save()
		companyinfo = self.get_object(company)
		data['subject'] = "Vendor Onboard Request from " + companyinfo.company_name
		data['from_address'] = 'info@zyllion.co'
		data['type'] = 5
		data['token'] = onboarddata.id
		emaildata = {"vendor_name":onboarddata.vendor_name, "company_name":companyinfo.company_name,
					 "token":token, "email":companyinfo.contactinfo.first().email}
		data['text'] = render_to_string('onboard.html', emaildata)
		emailserializer = self.serializer_class_Email(data=self.request.data)
		emailserializer.is_valid(raise_exception=True)
		emailserializer.save()
		mail.send_mail(data['subject'], strip_tags(data['text']), data['from_address'], [data['to_address']],
					   html_message=data['text'])
		jsondata = {"id":onboarddata.id, "company":onboarddata.company.id, "vendor_name":onboarddata.vendor_name,
					"to_address":onboarddata.to_address}
		return Response(jsondata, status=status.HTTP_201_CREATED)

class ListCompanyVendorOnboardPendingView(generics.ListAPIView):

	serializer_class = ListOnboardCompanyPendingSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_queryset(self):
		if self.request.user.account.plan.id == 4:
			raise CustomValidation('Bad Request', 'detail', 400)
		return Company.objects.filter(account=self.request.user.account.id)

class ResendVendorOnboardEmailView(generics.CreateAPIView):

	serializer_class = ResendVendorTokenSerializer
	serializer_class_Email = EmailCreationSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_object(self, company):
		return Company.objects.get(pk=company)

	def get_object_Token(self, id, company):
		return get_object_or_404(Token, pk=id, company=company, is_deleted=False, is_used=False)
	def create(self, request, *args, **kwargs):
		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			id = int(self.request.data.get('onboardvendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.id == 4 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		data = self.request.data
		onboardvendor = self.get_object_Token(id, company)
		token = str(uuid.uuid4())
		data['to_address'] = self.request.data.get('to_address') if self.request.data.get('to_address') else onboardvendor.to_address
		data['vendor_name'] = onboardvendor.vendor_name
		data['token'] = token

		tokenserializer = self.get_serializer(data=data)
		tokenserializer.is_valid(raise_exception=True)
		onboarddata = tokenserializer.save()
		#delete old onboard request
		onboardvendor.is_deleted = True
		onboardvendor.save()

		companyinfo = self.get_object(company)
		data['subject'] = "Vendor Onboard Request from " + companyinfo.company_name
		data['from_address'] = 'info@zyllion.co'
		data['type'] = 5
		data['token'] = onboarddata.id
		emaildata = {"vendor_name": onboarddata.vendor_name, "company_name": companyinfo.company_name,
					 "token": token, "email": companyinfo.contactinfo.first().email}
		data['text'] = render_to_string('onboard.html', emaildata)
		emailserializer = self.serializer_class_Email(data=self.request.data)
		emailserializer.is_valid(raise_exception=True)
		emailserializer.save()
		#send the onboard email
		mail.send_mail(data['subject'], strip_tags(data['text']), data['from_address'], [data['to_address']], html_message=data['text'])
		jsondata = {"id": onboarddata.id, "company": onboarddata.company.id,
					"vendor_name": onboarddata.vendor_name,
					"to_address": onboarddata.to_address}
		return Response(jsondata, status=status.HTTP_201_CREATED)



class DeleteVendorOnBoardRequestView(generics.UpdateAPIView):

	serializer_class = DeleteOnboardVendorRequestSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_object(self):
		return get_object_or_404(Token, pk=int(self.request.data.get('onboardvendor', 0)), company=int(self.request.data.get('company', 0)), is_used=False)

	def perform_update(self, serializer):

		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			int(self.request.data.get('onboardvendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.parent.id != 7 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		serializer.save(is_deleted=True)

class HideReceivedVendorOnboardRequestView(generics.UpdateAPIView):
	serializer_class = HideReceivedVendorOnboardRequestSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_object(self):
		return get_object_or_404(Token, pk=int(self.request.data.get('onboardvendor', 0)), company=int(self.request.data.get('company', 0)), is_used=True, is_deleted=False, is_hidden=False)

	def perform_update(self, serializer):

		compids = [comp.id for comp in self.request.user.company.all()]
		try:
			int(self.request.data.get('onboardvendor', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		try:
			company = int(self.request.data.get('company', 0))
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		if self.request.user.account.plan.parent.id != 7 or company not in compids or company == 0:
			raise CustomValidation('Bad Request', 'detail', 400)

		serializer.save(is_hidden=True)

class RetrieveVendorOnboardSetupView(generics.RetrieveAPIView):

	serializer_class = RetrieveOnboardVendorSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_object(self):
		try:
			token = self.kwargs.get('token')
		except ValueError:
			raise CustomValidation('Bad Request', 'detail', 400)
		tokendata =  get_object_or_404(Token, token=token, is_deleted=False, is_used=False)
		time_between_create = timezone.now() - tokendata.date_created
		if time_between_create.days > 10:
			raise CustomValidation('Token has expired', 'detail', 400)
		return tokendata

class UtilityOnboardVendorView(generics.CreateAPIView):

	serializer_class_Vendor = SaveOnboardVendorSerializer
	serializer_class_CompanyLink = CompanyLinkSerializer
	serializer_class_w9 = SaveOnboardW9DataSerializer
	serializer_class_ContactInfo = SaveOnboardContactInfoDataSerializer
	serializer_class_BankInfo = SaveOnboardBankInfoDataSerializer
	serializer_class_Term = SaveOnboardTermSerializer
	permission_classes = [permissions.AllowAny]

	def get_queryset_Token(self):
		return Token.objects.filter(token=self.request.data.get('token'), is_deleted=False, is_used=False, is_hidden=False).first()

	def create(self, request, *args, **kwargs):
		dt = datetime.now(timezone.utc)
		vendor_data = self.request.data
		w9 = vendor_data.get('w9')
		# validation checks for zyllion tokens
		if vendor_data == None:
			raise CustomValidation('No data passed', 'detail', 400)
		tokendata = self.get_queryset_Token()
		#tokendata = get_refresh_tokens_by_zyllion_token(vendor_data.get('token', ''))
		if not tokendata:
			raise CustomValidation('Invalid Token', 'detail', 400)
		time_since_issued = dt - tokendata.date_created
		if time_since_issued.days > 10:
			raise CustomValidation('Link has Expired', 'detail', 400)
		# general validation checks:
		if not vendor_data.get('w9') or not vendor_data.get('bank') or not vendor_data.get('contact') or not vendor_data.get('term'):
			raise CustomValidation('Incorrect Data Structure', 'detail', 400)
		# validation checks for w9 information
		for key, value in w9.items():
			if key in ['name', 'tax_class', 'address', 'location', 'tin', 'signature'] and not value:
				raise CustomValidation(key + " is required", "detail", 400)
		if not all(elem in list(w9.keys()) for elem in ['name', 'tax_class', 'address', 'location', 'tin', 'signature']):
			raise CustomValidation("Required field is empty", "detail", 400)
		tcounter = 0
		for key, value in json.loads(w9.get('tax_class')).items():
			if key == "Limited liability company" and value not in ['false', 'S', 'C', 'P']:
				raise CustomValidation('Invalid tax_class selected', 'detail', 400)
			if value:
				tcounter += 1
		if tcounter > 1:
			raise CustomValidation('Only one tax_class may be selected', 'detail', 400)
		tin = json.loads(w9.get('tin'))
		if tin.get('ssn') and tin.get('ein'):
			raise CustomValidation("Only one tin may be entered", "detail", 400)
		if not tin.get('ssn') and not tin.get('ein'):
			raise CustomValidation("At least one tin must be entered", "detail", 400)
		if not re.match("^\d{2}\-\d{7}$", tin.get('ein')) and not re.match("^\d{3}-\d{2}-\d{4}$", tin.get('ssn')):
			raise CustomValidation("Invalid tin format entered", "detail", 400)
		if len(w9.get('signature')) < 200 or 'svg+xml;base64' not in w9.get('signature'):
			raise CustomValidation('Invalid image uploaded', 'detail', 400)

		data = {}
		data.update(self.request.data['w9'])
		data.update(self.request.data['bank'])
		data.update(self.request.data['contact'])
		data['tin'] = encryptdict({'ein': tin.get('ein', '').replace('-', '').replace(' ', ''), 'ssn': tin.get('ssn', '').replace('-', '').replace(' ', '')}, ['ein', 'ssn'])
		data['acctinfo'] = encryptdict(self.request.data.get('bank'), ['routing_num', 'account_num'])
		data['account_numbers'] = f.encrypt(data.get('account_numbers').encode()).decode('utf-8')
		data['year'] = w9_years[-1]
		tokenobj = tokendata
		data['token'] = tokenobj
		vendor = self.serializer_class_Vendor(data=data)
		vendor.is_valid(raise_exception=True)
		vend = vendor.save()
		data['vendor'] = vend.id
		data['company'] = tokenobj.company.id
		companylink = self.serializer_class_CompanyLink(data=data)
		companylink.is_valid(raise_exception=True)
		cl = companylink.save()
		data['companylink'] = cl.id

		w9 = self.serializer_class_w9(data=data)
		contactinfo = self.serializer_class_ContactInfo(data=data)
		bankinfo = self.serializer_class_BankInfo(data=data)
		term = self.serializer_class_Term(data=data)
		w9.is_valid(raise_exception=True)
		contactinfo.is_valid(raise_exception=True)
		bankinfo.is_valid(raise_exception=True)
		term.is_valid(raise_exception=True)
		w9.save()
		contactinfo.save()
		bankinfo.save()
		term.save()
		tokenobj.is_used = True
		tokenobj.companylink = cl
		tokenobj.save()
		return Response({"company_name":vend.company_name, "vendor_id":vend.id})

class ListCompanyVendorOnboardReceivedView(generics.ListAPIView):
	serializer_class = ListOnboardCompanyReceivedSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_queryset(self):
		if self.request.user.account.plan.id == 4:
			raise CustomValidation('Bad Request', 'detail', 400)
		return Company.objects.filter(account=self.request.user.account.id)

class ScriptTestView(generics.ListAPIView):

	serializer_class = ListOnboardCompanyReceivedSerializer
	permission_classes = [permissions.AllowAny]

	def list(self, request, *args, **kwargs):
		command = ["bash","data/scripts/file_manipulater.sh","create" ]
		try:
				process = Popen(command, stdout=PIPE, stderr=STDOUT)
				output = process.stdout.read()
				exitstatus = process.poll()
				if (exitstatus==0):
					return Response({"status": "Success", "output":str(output)})
				else:
					return Response({"status": "Failed", "output":str(output)})
		except Exception as e:
				return {"status": "failed", "output":str(e)}

class UtilityCreateTermsView(generics.CreateAPIView):

	serializer_class=UtilityTermCreateSerializer
	model=Term

	def get_queryset(self):
		return Company.objects.filter(account=self.request.user.account.id).last()
	def create(self, request, *args, **kwargs):
		company = self.get_queryset()
		TermSerializer = self.get_serializer(data=self.request.data, many=isinstance(self.request.data, list))
		TermSerializer.is_valid(raise_exception=True)
		terms = TermSerializer.save(company=company)
		termlist = [{"id":term.id, "name": term.term} for term in terms]
		return Response(termlist)

class AccountStatus(generics.ListAPIView):

	model = User
	permission_classes = [permissions.IsAuthenticated, IsUser]

	def list(self, request, *args, **kwargs):
		user = User.objects.get(id=self.request.user.id)
		w9 = self.w9(user)
		bankinfo = self.bankinfo(user)
		user_count = self.user_limit(user)
		try:
			if type(user_count) != str:
				r  = {'w9_completed':w9, "bank_info_completed":bankinfo, "account_active":user.account.is_active}
			return Response( dict(r, **user_count))
		except Exception as e:
			raise CustomValidation(user_count, 'detail', 400)
	def w9(self, user):
		if user.company.first() is None:
			return False
		if user.company.first().taxform_set.last() is None:
			return False
		else:
			return True
	def bankinfo(self, user):
		if user.company.first() is None:
			return False
		if user.company.first().bankinfo.last() is None:
			return False
		else:
			return True
	def user_limit(self, user):
		user_count = user.account.user_set.filter(is_active=True).count()
		allowed_users = user.account.num_users
		return {'active_users': user_count, 'allowed_users': allowed_users}

class AccountCardUpdateView(views.APIView):
	"""
	Use this endpoint to log out all sessions for a given user.
	"""
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def post(self, request, *args, **kwargs):
		card = update_card(self.request)
		if card:
			return Response({"detail":"Card Updated"}, status=status.HTTP_204_NO_CONTENT)
		else:
			return Response({"detail":"Error updating Card"})

class AccountDeactivateView(generics.UpdateAPIView):

	permission_classes = [permissions.IsAuthenticated, IsAcctManager]
	serializer_class = DeactivateAccountSerializer

	def get_object(self):
		return get_object_or_404(Account, pk=self.request.user.account.id)

	def perform_update(self, serializer):

		deactivation = cancel_subscription(self.request)
		if not deactivation:
			raise CustomValidation('Error deleting account', 'detail', 400)
		else:
			serializer.save(is_active=False, plan=None)

class ReactivateAccountView(generics.UpdateAPIView):
	"""
	Reactivate an account that has cancelled
	"""
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]
	serializer_class = ReactivateAccountSerializer

	def get_object(self):
		return get_object_or_404(Account, pk=self.request.user.account.id)

	def perform_update(self, serializer):
		if self.request.user.account.is_active  == False:
			reactivation = reactivate_subscription(self.request, self.request.data)
			if not reactivation:
				raise CustomValidation('Error reactivating account', 'detail', 400)
			else:
				serializer.save(is_active=True)
		else:
			raise CustomValidation('Active account cannot be reactivated', 'detail', 400)


class UpdateCompanyBankInfoView(generics.UpdateAPIView):
	"""
	Update a Company's BankInformation
	"""
	serializer_class = UpdateCompanyBankInformationSerializer
	permission_classes = [permissions.IsAuthenticated, IsAcctManager]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_object(self):
		try:
			return get_object_or_404(BankInformation, company=self.request.data.get('company'))
		except:
			raise CustomValidation("This field is required", "company", 400)


	def perform_update(self, serializer):
		user_companies = [company.id for company in self.request.user.company.all()]
		if self.request.data.get('company') not in user_companies:
			raise CustomValidation('Bad Request', 'detail', 400)
		else:
			acctinfo = encryptdict(self.request.data.get('bank'), ['routing_num', 'account_num'])
			bankinfo = serializer.save(acctinfo=acctinfo)
		return Response({"company_id":self.request.data.get('company'), "id": bankinfo.id}, status=status.HTTP_200_OK)

class ListCompanyVendorOnboardAllView(generics.ListAPIView):
	serializer_class = ListOnboardCompanyAllSerializer
	permission_classes = [permissions.IsAuthenticated, IsOnboardUser]

	def get_serializer_context(self):
		return {"request": self.request}

	def get_queryset(self):
		if self.request.user.account.plan.parent_id !=7:
			raise CustomValidation('Bad Request', 'detail', 400)
		return Company.objects.filter(account=self.request.user.account.id)