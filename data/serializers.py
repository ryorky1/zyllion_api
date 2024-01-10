from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
from django.contrib.auth.models import Group
from django.db import IntegrityError, transaction
from .utils import number_obfuscator, encryptdict, decryptdict, get_month_first_last_day, allowed_onboard_req_int
User = get_user_model()
import re
from django.core.exceptions import ObjectDoesNotExist
from .exceptions import CustomValidation
from rest_framework import status
from django.utils import timezone
from datetime import datetime
from decouple import config
from cryptography.fernet import Fernet
import copy
from django.contrib.auth.forms import PasswordResetForm
from django.conf import settings
from django.utils.translation import gettext as _
import json

"""
Global variables
"""
excludeemail = ['ar@zyllion.co', 'ap@zyllion.co']
emaildomain = 'zyllion.co'
f = Fernet(config('CRYPTOKEY'))
"""
Validators
"""
def valid_phone(value):
    if (value['country'].lower() == 'us' or value['country'].lower() == 'united states') \
            and not re.match('^\(?\d{3}\)?[\s.-]?\d{3}[\s.-]\d{4}$', value['phone']):
        raise serializers.ValidationError({"phone": "Invalid phone number entered"})

def useremail_check(value):
    email=value.get('email', None)
    if email:
        if email.split('@')[1].lower() == emaildomain:
            raise serializers.ValidationError({"email":"Email cannot end with "+emaildomain})

def password_checker(value):
    #validation rule:  at least one uppercase letter, 1 special character, 1 digit, 1lowercase letter,
    # and be between 8 and 64 characters in length
    password = value.get('password', None)
    goodpassword = password if password else value['new_password']
    if not re.match("(?=.*[A-Z])(?=.*[@%+/'!#$^?:,(){}[~])(?=.*[0-9])(?=.*[a-z]).{8,64}", goodpassword):
        raise serializers.ValidationError({"password":"Password does not meet required strength rules"})

def valid_city(value):
    if  not re.match('^[a-zA-Z\u0080-\u024F]+(?:([\ \-\']|(\.\ ))[a-zA-Z\u0080-\u024F]+)*$', value['city']):
        raise serializers.ValidationError({"city":"City can only contain letters and spaces"})

def valid_state(value):
    if  not re.match('^[a-zA-Z\u0080-\u024F]+(?:([\ \-\']|(\.\ ))[a-zA-Z\u0080-\u024F]+)*$', value['state']):
        raise serializers.ValidationError({"city":"City can only contain letters and spaces"})

def valid_country(value):
    if  not re.match('^[a-zA-Z\u0080-\u024F]+(?:([\ \-\']|(\.\ ))[a-zA-Z\u0080-\u024F]+)*$', value['country']):
        raise serializers.ValidationError({"city":"City can only contain letters and spaces"})

class ContactInfoCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInfo
        fields = '__all__'
        validators = [valid_phone, valid_city, valid_state, valid_country]

#make payment_id, date_created write_only
class AccountCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ('id', 'company_name', 'contact_name', 'is_active', 'is_verified', 'date_created', 'plan', 'num_users')

class ContactInfoListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInfo
        fields = ('phone', 'ext', 'address1','address2', 'city', 'state', 'zip', 'country', 'email')

class ContactInfoCreateUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInfo
        fields = ('phone', 'ext', 'address1','address2', 'city', 'state', 'zip', 'country', 'email')
        validators = [valid_phone, valid_city, valid_state, valid_country]

class PlansListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = ('id', 'plan_name', 'plan_text', 'price', 'is_active', 'is_displayed', 'allowed_users')

class PaymentMethodListSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = ('id','method')

class AccountPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = Plan
        fields = ('id', 'plan_name')

class AccountDetailSerializer(serializers.ModelSerializer):
    plan = AccountPlanSerializer()
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret['allowed_users'] = ret['num_users']
        del ret['num_users']
        return ret

    class Meta:
        model = Account
        fields = ('id', 'company_name', 'contact_name', 'is_active', 'plan', 'num_users', 'ap_email', 'ar_email', 'contactinfo')


class AccountUpdateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)

    class Meta:
        model = Account
        fields = ('id', 'company_name', 'contact_name', 'is_active', 'ap_email', 'ar_email','contactinfo', 'plan')

    def validate(self, data):
        apemail = data.get('ap_email', None)
        aremail = data.get('ar_email', None)
        plan_id = data.get('plan', self.context['request'].user.account.plan).id
        parent_plan = data.get('plan', self.context['request'].user.account.plan).parent_id
        accountid = self.context['request'].user.account.id
        apemailcheck = Account.objects.filter(ap_email=apemail).exclude(
            pk=accountid).exists() | Account.objects.filter(
            ar_email=apemail).exclude(pk=accountid).exists()
        aremailcheck = Account.objects.filter(ap_email=aremail).exclude(
            pk=accountid).exists() | Account.objects.filter(
            ar_email=aremail).exclude(pk=accountid).exists()
        if plan_id == 3:
            if not apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account"})
            if aremail:
                raise serializers.ValidationError({"ar_email": "AR email Address is not permitted for this Account"})
        if plan_id == 4:
            if not aremail:
                raise serializers.ValidationError({"ar_email": "AR email Address is required for this Account"})
            if apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is not permitted for this Account"})
        if plan_id in [2, 5, 6]:
            if not apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account"})
            if not apemail:
                raise serializers.ValidationError({"ar_email": "AR email Address is required for this Account"})
            if not apemail and not aremail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account",
                                                   "ar_email":"AR email Address is required for this Account"})
        if parent_plan != 7:
            if apemail is not None and apemail.split('@')[1].lower() != emaildomain:
                raise serializers.ValidationError({"ap_email": "Email must end with " + emaildomain})
            if aremail is not None and aremail.split('@')[1].lower() != emaildomain:
                raise serializers.ValidationError({"ar_email": "Email must end with " + emaildomain})
            if apemail == aremail:
                raise serializers.ValidationError({"ap_email": "AP email and AR email must be different"})
            if apemailcheck == True or apemail in excludeemail:
                raise serializers.ValidationError({"ap_email": "Email already exists"})
            if aremailcheck == True or aremail in excludeemail:
                raise serializers.ValidationError({"ar_email": "Email already exists"})
        return data

    def update(self, instance, validated_data):

        try:
            account = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_create_account')
        return account


    def perform_update(self, instance, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        contacts = (instance.contactinfo).all()
        contacts = list(contacts)
        instance.company_name = validated_data.get('company_name', instance.company_name)
        instance.contact_name = validated_data.get('contact_name', instance.contact_name)
        instance.num_users = validated_data.get('num_users', instance.num_users)
        instance.ap_email = validated_data.get('ap_email', instance.ap_email)
        instance.ar_email = validated_data.get('ar_email', instance.ar_email)
        instance.plan_id = validated_data.get('plan', instance.plan_id)
        instance.save()
        for contact_data in contacts_data:
            contact = contacts.pop(0)
            contact.phone = contact_data.get('phone', contact.phone)
            contact.ext = contact_data.get('ext', contact.ext)
            contact.address1 = contact_data.get('address1', contact.address1)
            contact.address2 = contact_data.get('address2', contact.address2)
            contact.city = contact_data.get('city', contact.city)
            contact.state = contact_data.get('state', contact.state)
            contact.zip = contact_data.get('zip', contact.zip)
            contact.country = contact_data.get('country', contact.country)
            contact.email = contact_data.get('email', contact.email)
            contact.save()

        return instance

class AccountInfoUpdateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)

    class Meta:
        model = Account
        fields = ('id', 'company_name', 'contact_name', 'ap_email', 'ar_email','contactinfo')

    def validate(self, data):
        apemail = data.get('ap_email', None)
        aremail = data.get('ar_email', None)
        plan_id = data.get('plan', self.context['request'].user.account.plan).id
        parent_plan = data.get('plan', self.context['request'].user.account.plan).parent_id
        accountid = self.context['request'].user.account.id
        apemailcheck = Account.objects.filter(ap_email=apemail).exclude(
            pk=accountid).exists() | Account.objects.filter(
            ar_email=apemail).exclude(pk=accountid).exists()
        aremailcheck = Account.objects.filter(ap_email=aremail).exclude(
            pk=accountid).exists() | Account.objects.filter(
            ar_email=aremail).exclude(pk=accountid).exists()
        if plan_id == 3:
            if not apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account"})
            if aremail:
                raise serializers.ValidationError({"ar_email": "AR email Address is not permitted for this Account"})
        if plan_id == 4:
            if not aremail:
                raise serializers.ValidationError({"ar_email": "AR email Address is required for this Account"})
            if apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is not permitted for this Account"})
        if plan_id in [2, 5, 6]:
            if not apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account"})
            if not apemail:
                raise serializers.ValidationError({"ar_email": "AR email Address is required for this Account"})
            if not apemail and not aremail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account",
                                                   "ar_email":"AR email Address is required for this Account"})
        if parent_plan != 7:
            if apemail is not None and apemail.split('@')[1].lower() != emaildomain:
                raise serializers.ValidationError({"ap_email": "Email must end with " + emaildomain})
            if aremail is not None and aremail.split('@')[1].lower() != emaildomain:
                raise serializers.ValidationError({"ar_email": "Email must end with " + emaildomain})
            if apemail == aremail:
                raise serializers.ValidationError({"ap_email": "AP email and AR email must be different"})
            if apemailcheck == True or apemail in excludeemail:
                raise serializers.ValidationError({"ap_email": "Email already exists"})
            if aremailcheck == True or aremail in excludeemail:
                raise serializers.ValidationError({"ar_email": "Email already exists"})
        return data

    def update(self, instance, validated_data):

        try:
            account = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_create_account')
        return account


    def perform_update(self, instance, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        contacts = (instance.contactinfo).all()
        contacts = list(contacts)
        instance.company_name = validated_data.get('company_name', instance.company_name)
        instance.contact_name = validated_data.get('contact_name', instance.contact_name)
        instance.num_users = validated_data.get('num_users', instance.num_users)
        instance.ap_email = validated_data.get('ap_email', instance.ap_email)
        instance.ar_email = validated_data.get('ar_email', instance.ar_email)
        instance.save()
        for contact_data in contacts_data:
            contact = contacts.pop(0)
            contact.phone = contact_data.get('phone', contact.phone)
            contact.ext = contact_data.get('ext', contact.ext)
            contact.address1 = contact_data.get('address1', contact.address1)
            contact.address2 = contact_data.get('address2', contact.address2)
            contact.city = contact_data.get('city', contact.city)
            contact.state = contact_data.get('state', contact.state)
            contact.zip = contact_data.get('zip', contact.zip)
            contact.country = contact_data.get('country', contact.country)
            contact.email = contact_data.get('email', contact.email)
            contact.save()

        return instance

class AccountPlanUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ('id', 'plan')

    def update(self, instance, validated_data):

        try:
            account = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_create_account')
        return account

    def perform_update(self, instance, validated_data):
        instance.num_users = validated_data.get('num_users', instance.num_users)
        instance.plan_id = validated_data.get('plan', instance.plan_id)
        instance.save()

        return instance

    def validate(self, data):
        request = self.context['request']
        if request.user.account.plan.id == request.data.get('plan'):
            raise CustomValidation('Plan is is already selected', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
        return data

class AccountPlanLogSerializer(serializers.ModelSerializer):

    class Meta:
        model = AccountPlanLog
        fields = '__all__'

class ListSystemSerializer(serializers.ModelSerializer):

    class Meta:
        model = System
        fields = ('id', 'name')

#make date_created, date_updated write_only
class CompanyCreateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoListSerializer(many=True)
    class Meta:
        model = Company
        fields = ('id','sys_company_id', 'company_name', 'date_created', 'date_updated', 'contactinfo')

    def create(self, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        company = Company.objects.create(**validated_data)
        for contact_data in contacts_data:
            ContactInfo.objects.create(**contact_data, company_id=company.id)
        return company

#make date_created, date_updated write_only
class CustomerCreateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoListSerializer(many=True)
    class Meta:
        model = Customer
        fields = ('id','sys_customer_id', 'company_name', 'date_created', 'date_updated', 'contactinfo')

    def create(self, validated_data):
        customer = self.perform_create(validated_data)
        return customer

    def perform_create(self, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        customer = Customer.objects.create(**validated_data)
        for contact_data in contacts_data:
            ContactInfo.objects.create(**contact_data, customer_id=customer.id)
        return customer

#make date_created, date_updated write_only
class VendorCreateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoListSerializer(many=True)
    class Meta:
        model = Vendor
        fields = ('id','sys_vendor_id', 'company_name', 'date_created', 'date_updated', 'contactinfo')

    def create(self, validated_data):
        vendor = self.perform_create(validated_data)
        return vendor

    def perform_create(self, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        vendor = Vendor.objects.create(**validated_data)
        for contact_data in contacts_data:
            ContactInfo.objects.create(**contact_data, vendor_id=vendor.id)
        return vendor

class CompanyUpdateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)
    class Meta:
        model = Company
        fields = ('id', 'company_name', 'contactinfo')

    def validate(self, data):
        cid = self.context['request'].data['compid']
        usercompanies = self.context['request'].user.company.all()
        companieslist = [c.id for c in usercompanies]
        if cid not in companieslist:
            raise CustomValidation('Access denied', 'detail', status_code=status.HTTP_403_FORBIDDEN)
        try:
            businesscheck = Company.objects.get(pk=cid)
        except ObjectDoesNotExist:
            businesscheck = None
        if not businesscheck:
            raise CustomValidation('Access denied', 'detail', status_code=status.HTTP_403_FORBIDDEN)
        return data

    def update(self, instance, validated_data):

        try:
            company = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_update_company')
        return company


    def perform_update(self, instance, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        contacts = (instance.contactinfo).all()
        contacts = list(contacts)
        instance.company_name = validated_data.get('company_name', instance.company_name)
        instance.save()
        for contact_data in contacts_data:
            contact = contacts.pop(0)
            contact.phone = contact_data.get('phone', contact.phone)
            contact.ext = contact_data.get('ext', contact.ext)
            contact.address1 = contact_data.get('address1', contact.address1)
            contact.address2 = contact_data.get('address2', contact.address2)
            contact.city = contact_data.get('city', contact.city)
            contact.state = contact_data.get('state', contact.state)
            contact.zip = contact_data.get('zip', contact.zip)
            contact.country = contact_data.get('country', contact.country)
            contact.email = contact_data.get('email', contact.email)
            contact.save()
        return instance

class CustomerUpdateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)
    class Meta:
        model = Customer
        fields = ('id', 'company_name', 'contactinfo')

    def update(self, instance, validated_data):

        try:
            company = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_update_company')
        return company


    def perform_update(self, instance, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        contacts = (instance.contactinfo).all()
        contacts = list(contacts)
        instance.company_name = validated_data.get('company_name', instance.company_name)
        instance.save()
        for contact_data in contacts_data:
            contact = contacts.pop(0)
            contact.phone = contact_data.get('phone', contact.phone)
            contact.ext = contact_data.get('ext', contact.ext)
            contact.address1 = contact_data.get('address1', contact.address1)
            contact.address2 = contact_data.get('address2', contact.address2)
            contact.city = contact_data.get('city', contact.city)
            contact.state = contact_data.get('state', contact.state)
            contact.zip = contact_data.get('zip', contact.zip)
            contact.country = contact_data.get('country', contact.country)
            contact.email = contact_data.get('email', contact.email)
            contact.save()
        return instance

class VendorUpdateSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)
    class Meta:
        model = Vendor
        fields = ('id', 'company_name', 'contactinfo')

    def update(self, instance, validated_data):

        try:
            company = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_update_company')
        return company


    def perform_update(self, instance, validated_data):
        contacts_data = validated_data.pop('contactinfo')
        contacts = (instance.contactinfo).all()
        contacts = list(contacts)
        instance.company_name = validated_data.get('company_name', instance.company_name)
        instance.save()
        for contact_data in contacts_data:
            contact = contacts.pop(0)
            contact.phone = contact_data.get('phone', contact.phone)
            contact.ext = contact_data.get('ext', contact.ext)
            contact.address1 = contact_data.get('address1', contact.address1)
            contact.address2 = contact_data.get('address2', contact.address2)
            contact.city = contact_data.get('city', contact.city)
            contact.state = contact_data.get('state', contact.state)
            contact.zip = contact_data.get('zip', contact.zip)
            contact.country = contact_data.get('country', contact.country)
            contact.email = contact_data.get('email', contact.email)
            contact.save()
        return instance

class CompanySerializer(serializers.ModelSerializer):

    class Meta:
        model = Company
        fields = '__all__'

class CompanyLinkSerializer(serializers.ModelSerializer):
    """
    Serializer for Linking Companies
    """
    class Meta:
        model = CompanyLink
        fields = '__all__'

class AcctRegistrationUserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer creating Users
    """
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )

    class Meta:
        model = User
        fields = ('id', 'password', 'first_name', 'last_name', 'is_admin', 'account', 'email', 'groups')
        validators=[password_checker, useremail_check]

    def create(self, validated_data):
        groups = validated_data.pop("groups")
        user = self.perform_create(validated_data, groups)
        return user

    def perform_create(self, validated_data, groups):
        user = User.objects.create_user(**validated_data)
        if isinstance(groups, list):
            groups = Group.objects.filter(pk__in=groups)
        if isinstance(groups, int):
            groups = Group.objects.get(pk=groups)
        user.group_list = []
        for group in groups:
            group.user_set.add(user)
            user.group_list.append(group.id)
        return user



class UserCreateSerializer(serializers.ModelSerializer):
    """
    Serializer creating Users
    """
    password = serializers.CharField(
        style={'input_type': 'password'},
        write_only=True
    )

    class Meta:
        model = User
        fields = ('id', 'password', 'first_name', 'last_name', 'is_admin', 'account', 'email', 'groups')
        validators=[password_checker, useremail_check]

    def create(self, validated_data):
        groups = validated_data.pop("groups")
        user = self.perform_create(validated_data, groups)
        return user

    def perform_create(self, validated_data, groups):
        user = User.objects.create_user(**validated_data)
        if isinstance(groups, list):
            groups = Group.objects.filter(pk__in=groups)
        if isinstance(groups, int):
            groups = Group.objects.get(pk=groups)
        user.group_list = []
        for group in groups:
            group.user_set.add(user)
            user.group_list.append(group.id)
        return user

    def validate(self, data):
        request = self.context['request']
        init_user = User.objects.filter(account=request.user.account.id).first()
        curr_user_groups = [g.id for g in request.user.groups.all()]
        groups = request.data.get('groups', [])
        groupset = set(groups)
        if len(groups) < 1:
            raise CustomValidation('No Groups Provided', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
        for group in groups:
            if not isinstance(group,int):
                    raise CustomValidation('Invalid Groups Provided', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
        if init_user.id != request.user.id:
            if 2 in curr_user_groups and request.user.id == init_user:
                pass
            elif 2 in curr_user_groups and request.user.id != init_user and not all(x in [3, 4, 5, 6, 7]  for x in groupset):
                raise CustomValidation('Insifficient Privaledges to Add User to Group', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
            elif 3 in curr_user_groups and 5 in curr_user_groups and not all(x in [4, 6, 7] for x in groupset):
                raise CustomValidation('Insifficient Privaledges to Add User to Group', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
            elif 3 in curr_user_groups and 5 not in curr_user_groups and not all(x in [4, 7] for x in groupset):
                raise CustomValidation('Insifficient Privaledges to Add User to Group', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
            elif 5 in curr_user_groups and 3 not in curr_user_groups and not all(x in [6] for x in groupset):
                raise CustomValidation('Insifficient Privaledges to Add User to Group', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
        if not request.user.company.first():
            raise CustomValidation('No Company Provided', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
        if sum(x in request.data['user_companies'] for x in request.data['company']) == 0:
            raise CustomValidation('Invalid Company provided', 'detail', status_code=status.HTTP_400_BAD_REQUEST)
        return data

class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for Updating User Information minus password
    """
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'email')
        validators = [useremail_check]

class UserActivationSerializer(serializers.ModelSerializer):
    """
    Serializer for Activating/Deactivating a User
    """
    class Meta:
        model = User
        fields = ('id','is_active')

class UserAdminUpdateSerializer(serializers.ModelSerializer):
    """
    Admin/Manager Updating a user Minus password
    """
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'is_admin', 'is_active', 'company', 'account', 'email', 'groups')
        validators=[useremail_check]

    def validate(self, data):
        request = self.context['request']
        useraccount = User.objects.get(pk=self.context['request'].data['uid']).account.id
        if not useraccount == request.user.account.id:
            raise CustomValidation('Access denied', 'account', status_code=status.HTTP_403_FORBIDDEN)
        return data

class UserLogSerializer(serializers.ModelSerializer):
    """
    Serializer for Logging User Changes
    """
    class Meta:
        model = UserLog
        fields = '__all__'

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """

    class Meta:
        model = User
        fields = ('password', )
        validators = [password_checker]


    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class AccountListSerializer(serializers.ModelSerializer):

    class Meta:
        model = Account
        fields = ('id', 'company_name', 'contact_name', 'is_active', 'is_verified', 'ap_email', 'ar_email', 'plan',
                  'num_users')

class GroupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Group
        fields=('id', 'name')

class UserListSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)
    class Meta:
        model = User
        fields = ('id','first_name','last_name','email','is_active','account','company', 'groups')


class SystemSerializer(serializers.ModelSerializer):

    class Meta:
        model = System
        fields = ('id', 'name')

class PlanListSerializer(serializers.ModelSerializer):
    system_set = SystemSerializer(many=True)
    class Meta:
        model = Plan
        fields = ('id', 'plan_name', 'plan_text', 'description', 'price', 'allowed_users', 'per_user', 'allowed_onboard_requests', 'system_set')
        depth=1

class InvoiceLineCreateSerializer(serializers.ModelSerializer):
#here
    class Meta:
        model = InvoiceLine
        exclude = ('invoice','glaccount', 'acct_class', 'department', 'location')

class InvoiceCreateSerializer(serializers.ModelSerializer):
    invoicelines = InvoiceLineCreateSerializer(many=True)

    class Meta:
        model = Invoice

        fields = ('id', 'sys_invoice', 'created_date', 'received_date', \
                  'due_date', 'invoice_num', 'memo', 'invoice_date', 'term', 'other', 'shipping', \
                  'subtotal','tax', 'total', 'invoicelines')
    def create(self, validated_data):
        invoicelines = validated_data.pop('invoicelines')
        invoice = Invoice.objects.create(**validated_data)
        for invoiceline in invoicelines:
            InvoiceLine.objects.create(**invoiceline, invoice_id=invoice.id)
        return invoice

class InvoiceLineListSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvoiceLine
        fields = '__all__'

class DefaultInvoiceListSerializer(serializers.ModelSerializer):
#here
    class Meta:
        model = Invoice
        fields = ('id', \
                  #'invoice_upload',
                 'created_date', 'received_date', 'due_date', 'buyer', \
                 'status', 'vendor', 'acct_class', 'department', 'invoice_num', \
                 'location', 'memo', 'invoice_date', 'term', 'other', 'shipping', 'subtotal','tax', 'total', 'days_overdue','overdue_status')
        depth=1

class APInvoiceListSerializer(DefaultInvoiceListSerializer):
#here
    class Meta:
        model=Invoice
        fields = ('id', \
                 #'invoice_upload',
                 'created_date', 'received_date', 'due_date', \
                 'status', 'vendor', 'acct_class', 'department', 'invoice_num', \
                 'location', 'memo', 'invoice_date', 'term', 'other', 'shipping', 'subtotal','tax', 'total', 'days_overdue','overdue_status')
        depth=1
class ARInvoiceListSerializer(DefaultInvoiceListSerializer):
#here
    class Meta:
        model=Invoice
        fields = ('id',
                 #'invoice_upload',
                 'created_date', 'received_date', 'due_date', 'buyer', \
                 'status', 'acct_class', 'department', 'invoice_num', \
                 'location', 'memo', 'invoice_date', 'term', 'other', 'shipping', 'subtotal','tax', 'total', 'days_overdue','overdue_status')
        depth=1

class InvoiceLineUpdateSerializer(serializers.ModelSerializer):

    class Meta:
        model = InvoiceLine
        exclude = ('invoice',)

class InvoiceUpdateSerializer(serializers.ModelSerializer):
    invoicelines = InvoiceLineUpdateSerializer(many=True)
#here
    class Meta:
        model = Invoice
        fields = ('id', 'invoice_num', \
                  #'invoice_upload',
                 'created_date', 'received_date', 'due_date', 'buyer', \
                 'status', 'vendor', 'acct_class', 'credits_available', 'department', \
                 'location', 'companyaccount', 'memo', 'invoice_date', 'term', 'other', 'shipping', 'subtotal','tax', 'total', 'invoicelines')

    def update(self, instance, validated_data):
        try:
            company = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_update_account')
        return company


    def perform_update(self, instance, validated_data):
        invoicelines_data = validated_data.pop('invoicelines')
        invoicelines = (instance.invoicelines).all()
        invoicelines = list(invoicelines)
        instance.vendor = validated_data.get('vendor', instance.vendor)
        instance.buyer = validated_data.get('buyer', instance.buyer)
        instance.invoice_num = validated_data.get('invoice_num', instance.invoice_num)
        #instance.invoice_upload = validated_data.get('invoice_upload', instance.invoice_upload)
        instance.term = validated_data.get('term', instance.term)
        instance.credits_available = validated_data.get('credits_available', instance.credits_available)
        instance.department = validated_data.get('department', instance.department)
        instance.acct_class = validated_data.get('acct_class', instance.acct_class)
        instance.location = validated_data.get('location', instance.location)
        instance.memo = validated_data.get('memo', instance.memo)
        instance.invoice_date = validated_data.get('invoice_date', instance.invoice_date)
        instance.received_date = validated_data.get('received_date', instance.received_date)
        instance.due_date = validated_data.get('due_date', instance.due_date)
        instance.status = validated_data.get('status', instance.status)
        instance.subtotal = validated_data.get('subtotal', instance.subtotal)
        instance.shipping = validated_data.get('shipping', instance.shipping)
        instance.other = validated_data.get('other', instance.other)
        instance.tax = validated_data.get('tax', instance.tax)
        instance.total = validated_data.get('total', instance.total)
        instance.companyaccount = validated_data.get('companyaccount', instance.companyaccount)
        instance.acct_class = validated_data.get('acct_class', instance.acct_class)
        instance.department = validated_data.get('department', instance.department)
        instance.location = validated_data.get('location', instance.location)
        instance.save()
        for invoiceline_data in invoicelines_data:
            invoiceline = invoicelines.pop(0)
            invoiceline.product_number = invoiceline_data.get('product_number', invoiceline.product_number)
            invoiceline.description = invoiceline_data.get('description', invoiceline.description)
            invoiceline.qty = invoiceline_data.get('qty', invoiceline.qty)
            invoiceline.unit_price = invoiceline_data.get('unit_price', invoiceline.unit_price)
            invoiceline.line_tax = invoiceline_data.get('line_tax', invoiceline.line_tax)
            invoiceline.line_total = invoiceline_data.get('line_total', invoiceline.line_total)
            invoiceline.companyaccount = invoiceline_data.get('companyaccount', invoiceline.companyaccount)
            invoiceline.acct_class = invoiceline_data.get('acct_class', invoiceline.acct_class)
            invoiceline.department = invoiceline_data.get('department', invoiceline.department)
            invoiceline.glaccount = invoiceline_data.get('glaccount', invoiceline.glaccount)
            invoiceline.location = invoiceline_data.get('location', invoiceline.location)
            invoiceline.save()
        return instance

class InvoiceLogSerializer(serializers.ModelSerializer):

    class Meta:
        model=InvoiceLog
        fields=('modifier', 'companylink', 'invoice', 'status', 'action')

class AvaliableCompaniesSerializer(serializers.ModelSerializer):

    class Meta:
        model=Company
        fields = ('id', 'company_name')


class ChooseCompaniesSerializer(serializers.ModelSerializer):

    class Meta:
        model=Company
        fields = ('id', 'company_name')

class AppMenuBarUserSerializer(serializers.ModelSerializer):
    groups = GroupSerializer(many=True)
    class Meta:
        model=User
        fields=('id', 'first_name', 'last_name', 'email', 'groups')
        depth = 1

class SetupCompanyListSerializer(serializers.ModelSerializer):

    class Meta:
        model=Company
        fields=('id', 'company_name')

class SetupBankCreateSerializer(serializers.ModelSerializer):

    class Meta:
        model = BankInformation
        fields= '__all__'

    def validate(self, data):
        datacopy = copy.deepcopy(data)
        acctdata = decryptdict(datacopy.get('acctinfo'), ['account_num', 'routing_num'])
        if not acctdata.get('account_num') or not acctdata.get('account_num').isnumeric() or len(acctdata.get('account_num')) not in range(4, 17):
            raise (serializers.ValidationError({"account_num": "Invalid account number"}))
        if not acctdata.get('routing_num') or not acctdata.get('routing_num').isnumeric() or len(acctdata.get('routing_num')) not in range(8, 12):
            raise (serializers.ValidationError({"account_num": "Invalid routing number"}))
        return data



class SetupBankUpdateSerializer(serializers.ModelSerializer):


    class Meta:
        model = BankInformation
        fields= ('id', 'account_num', 'routing_num', 'company')

    def validate(self, data):
        accountnum = data.get('account_num', '')
        routingnum = data.get('routing_num', '')
        if not accountnum or not accountnum.isnumeric() or len(accountnum) not in range(4, 17):
            raise (serializers.ValidationError({"account_num": "Invalid account number"}))
        if not routingnum or not routingnum.isnumeric() or len(routingnum) not in range(8, 12):
            raise (serializers.ValidationError({"account_num": "Invalid routing number"}))
        return data

    def update(self, instance, validated_data):
        instance.account_num = validated_data.get('account_num', instance.account_num)
        instance.routing_num = validated_data.get('routing_num', instance.routing_num)
        instance.save()
        instance.account_num = number_obfuscator(instance.account_num)
        instance.routing_num = number_obfuscator(instance.routing_num)
        return instance

class SetupBankListSerializer(serializers.ModelSerializer):
    account_num = serializers.SerializerMethodField()
    routing_num = serializers.SerializerMethodField()

    class Meta:
        model=BankInformation
        fields = ('id', 'account_num', 'routing_num', 'company')

    def get_account_num(self, obj):
        return number_obfuscator(obj.account_num)

    def get_routing_num(self, obj):
        return number_obfuscator(obj.routing_num)

class SetupTaxFormSaveSerializer(serializers.ModelSerializer):

    class Meta:
        model=TaxForm
        fields = ('id', 'name', 'business_name', 'tax_class', 'exemption', 'address', 'location', 'account_numbers', 'tin', 'company', 'signature', 'year')
        extra_kwargs = {
            'name': {'write_only': True},
            'business_name': {'write_only': True},
            'tax_class': {'write_only': True},
            'exemption': {'write_only': True},
            'address': {'write_only': True},
            'location': {'write_only': True},
            'account_numbers': {'write_only': True},
            'tin': {'write_only': True},
            'company': {'write_only': True},
            'signature': {'write_only': True},
            'year':{'write_only': True},
        }
    def to_internal_value(self, data):
        data['company'] = Company.objects.get(pk=data.get('company'))
        if data.get('signature'):
            if data.get('signature', '').startswith('data:'):
                data['signature'] = data.get('signature')
            else:
                data['signature'] = 'data:' + data.get('signature')
            data['tin'] = encryptdict(data.get('tin'), ['ein', 'ssn'])
            data['account_numbers'] = f.encrypt(data.get('account_numbers').encode()).decode('utf-8')
        return data

    def validate(self, data):
        print(data)
        ##added this in b/c for some reason, field level validations stopped working
        required_fields = [f.name for f in TaxForm._meta.get_fields() if not getattr(f, 'blank', False) is True and not getattr(f, 'null', False) is True]
        required_fields.append('company')
        required_fields.remove('is_deleted')
        submitted_fields = list(data.keys())
        for field in required_fields:
            if field not in submitted_fields:
                raise (serializers.ValidationError({field: "This field is required"}))
        ##starting real validation
        tcounter = 0
        for key, value in data.get('tax_class').items():
            if key == "Limited liability company" and value not in ['false', 'S', 'C', 'P']:
                raise serializers.ValidationError({"tax_class": "Invalid tax_class selected"})
            if value:
                tcounter += 1
        if tcounter > 1:
            raise serializers.ValidationError({"tax_class": "Only one tax_class may be selected"})
        tin = decryptdict(data.get('tin'), ['ein', 'ssn'])
        if tin.get('ssn') and tin.get('ein'):
            raise serializers.ValidationError({"tin": "Only one tin may be entered"})
        if not tin.get('ssn') and not tin.get('ein'):
            raise serializers.ValidationError({"tin": "At least one tin must be entered"})
        if not re.match("^\d{2}\-\d{7}$", tin.get('ein')) and not re.match("^\d{3}-\d{2}-\d{4}$", tin.get('ssn')):
            raise serializers.ValidationError({"tin": "Invalid format entered"})
        if len(data['signature']) < 200 or 'svg+xml;base64' not in data['signature']:
            raise serializers.ValidationError({"signature": "Invalid image uploaded"})
        return data

    def create(self, validated_data):
        data = validated_data.copy()
        tin = data.get('tin')
        stin = {'ein': tin.get('ein', '').replace('-', '').replace(' ', ''), 'ssn': tin.get('ssn', '').replace('-', '').replace(' ', '')}
        data['tin'] = encryptdict(stin, ['ein', 'ssn'])
        return super(SetupTaxFormSaveSerializer, self).create(data)

class SetupTaxFormRetrieveSerializer(serializers.ModelSerializer):

    class Meta:
        model=TaxForm
        fields=('id','company', 'w9_upload')

class SetupEmailCreateSerializer(serializers.ModelSerializer):

    class Meta:
        model=Account
        fields=('id','ap_email', 'ar_email')

    def validate(self, data):
        apemail = data.get('ap_email', None)
        aremail = data.get('ar_email', None)
        plan_id = self.context['request'].user.account.plan.id
        accountid = self.context['request'].user.account.id
        apemailcheck = Account.objects.filter(ap_email=apemail).exclude(
            pk=accountid).exists() | Account.objects.filter(
            ar_email=apemail).exclude(pk=accountid).exists()
        aremailcheck = Account.objects.filter(ap_email=aremail).exclude(
            pk=accountid).exists() | Account.objects.filter(
            ar_email=aremail).exclude(pk=accountid).exists()
        if plan_id == 3:
            if not apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account"})
            if aremail:
                raise serializers.ValidationError({"ar_email": "AR email Address is not permitted for this Account"})
        if plan_id == 4:
            if not aremail:
                raise serializers.ValidationError({"ar_email": "AR email Address is required for this Account"})
            if apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is not permitted for this Account"})
        if plan_id in [2, 5, 6]:
            if not apemail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account"})
            if not apemail:
                raise serializers.ValidationError({"ar_email": "AR email Address is required for this Account"})
            if not apemail and not aremail:
                raise serializers.ValidationError({"ap_email": "AP email Address is required for this Account",
                                                   "ar_email":"AR email Address is required for this Account"})
        if apemail is not None and apemail.split('@')[1].lower() != emaildomain:
            raise serializers.ValidationError({"ap_email": "Email must end with " + emaildomain})
        if aremail is not None and aremail.split('@')[1].lower() != emaildomain:
            raise serializers.ValidationError({"ar_email": "Email must end with " + emaildomain})
        if apemail == aremail:
            raise serializers.ValidationError({"ap_email": "AP email and AR email must be different"})
        if (plan_id != 4 and apemailcheck == True) or apemail in excludeemail:
            raise serializers.ValidationError({"ap_email": "Email already exists"})
        if (plan_id != 3 and aremailcheck == True) or aremail in excludeemail:
            raise serializers.ValidationError({"ar_email": "Email already exists"})
        return data

class SetupSystemSaveSerializer(serializers.ModelSerializer):
    class Meta:
        model=Account
        fields=('id','system')

class APOverdueStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model=Invoice
        fields=('due_date', 'status')

class APInvoiceStatusesSerializer(serializers.ModelSerializer):
    class Meta:
        model=Status
        exclude=('status', 'type')

class FilteredBankListSerializer(serializers.ListSerializer):

    def to_representation(self, data):
        data = data.filter(is_deleted=False).order_by('-is_default', 'id')
        for i, bankinfo in enumerate(data):
            data[i].account_num = number_obfuscator(bankinfo.account_num)
        return super(FilteredBankListSerializer, self).to_representation(data)

class BankInfoSerializer(serializers.ModelSerializer):

    class Meta:
        list_serializer_class = FilteredBankListSerializer
        model = BankInformation
        fields = ('id','account_num', 'is_default')

class APCompanyInfoSettingsSerializer(serializers.ModelSerializer):
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)
    bankinfo = BankInfoSerializer(many=True)

    class Meta:
        model=Company
        fields = ('id', 'company_name','contactinfo', 'bankinfo')

class APCompanyAddBankAccountSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret['account_num'] = number_obfuscator(ret['account_num'])
        del ret['routing_num']
        return ret
    class Meta:
        model=BankInformation
        fields=('id', 'account_num', 'routing_num', 'company', 'is_default')

class APCompanySetDefaultSerializer(serializers.ModelSerializer):

    class Meta:
        model=BankInformation
        fields=('id', 'is_default')

class APCompanyDeleteBankAccountSerializer(serializers.ModelSerializer):

    class Meta:
        model=BankInformation
        fields=('id', 'is_deleted')

class APApproverListSerializer(serializers.ModelSerializer):

    class Meta:
        model=User
        fields=('id', 'first_name', 'last_name', 'email')

class PaymentOptionSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    class Meta:
        model = PaymentOption
        fields = ('id','paymentmethod', 'is_default', 'is_enabled', 'to_bank_acct', 'vendor_type')

    def to_internal_value(self, data):
        instance = super(PaymentOptionSerializer, self).to_internal_value(data)
        if "to_bank_acct" not in data:
            instance["to_bank_acct"] = None
        if "vendor_type" not in data:
            instance["vendor_type"] = None
        return instance

class CreateVendorPaymentPreferencesSerializer(serializers.ModelSerializer):
    paymentoptions = PaymentOptionSerializer(many=True)
    class Meta:
        model=PaymentPreference
        fields=('id', 'company', 'send_remittance_email', 'from_bank_acct', 'paymentoptions')

    def create(self, validated_data):
        paymentoptions = validated_data.pop('paymentoptions')
        paypreference = PaymentPreference.objects.create(**validated_data)
        for paymentoption in paymentoptions:
            PaymentOption.objects.create(**paymentoption, paymentpreference_id=paypreference.id)
        return paypreference

class UpdateVendorPaymentPreferencesSerializer(serializers.ModelSerializer):
    paymentpreference = PaymentOptionSerializer(many=True)
    class Meta:
        model=PaymentPreference
        fields=('id', 'company', 'send_remittance_email', 'from_bank_acct', 'paymentpreference')

    def update(self, instance, validated_data):

        try:
            preference = self.perform_update(instance, validated_data)
        except IntegrityError:
            self.fail('cannot_update_company')
        return preference
    def validate(self, data):
        default_set=0
        options = data['paymentpreference']
        for i, option in enumerate(options):
            if option['is_default'] == True or option['is_default'] == 1:
                default_set += 1
        if default_set > 1:
            raise serializers.ValidationError({"is_default": "Only one Payment Option may be set as a default"})
        return data
    def perform_update(self, instance, validated_data):
        paymentoptions = validated_data.pop('paymentpreference')
        instance.send_remittance_email = validated_data.get('send_remittance_email', instance.send_remittance_email)
        instance.from_bank_acct = validated_data.get('from_bank_acct', instance.from_bank_acct)
        instance.save()
        for option in paymentoptions:
            option_id = option.get('id', None)
            if option_id:
                payoption = PaymentOption.objects.get(id=option_id)
                payoption.is_default = option.get('is_default', payoption.is_default)
                payoption.is_enabled = option.get('is_enabled', payoption.is_enabled)
                payoption.to_bank_acct = option.get('to_bank_acct', payoption.to_bank_acct)
                payoption.vendor_type = option.get('vendor_type', payoption.vendor_type)
                payoption.save()
        return instance

class PaymentOptionListSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    paymentmethod = serializers.SerializerMethodField()
    to_bank_acct = serializers.SerializerMethodField()
    vendor_type = serializers.SerializerMethodField()
    class Meta:
        model = PaymentOption
        fields = ('id','paymentmethod', 'is_default', 'is_enabled', 'to_bank_acct', 'vendor_type')

    def get_paymentmethod(self, obj):
        if obj.paymentmethod is not None:
            return {"id": (obj.paymentmethod.id), "method": (obj.paymentmethod.method)}
        else:
            pass
    def get_to_bank_acct(self, obj):
        if obj.to_bank_acct is not None:
            return {"id": (obj.to_bank_acct.id), "account_num": number_obfuscator(obj.to_bank_acct.account_num)}
        else:
            pass
    def get_vendor_type(self, obj):
        if obj.vendor_type is not None:
            return {"id": (obj.vendor_type.id), "type": (obj.vendor_type.type)}
        else:
            pass

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if ret['to_bank_acct'] is None:
            del ret['to_bank_acct']
        if ret['vendor_type'] is None:
            del ret['vendor_type']
        return ret

class ListVendorPaymentPreferencesSerializer(serializers.ModelSerializer):
    paymentpreference = PaymentOptionListSerializer(many=True)
    from_bank_acct = serializers.SerializerMethodField()
    class Meta:
        model=PaymentPreference
        fields=('id', 'companylink', 'send_remittance_email', 'from_bank_acct', 'paymentpreference')

    def get_from_bank_acct(self, obj):
        if obj.from_bank_acct is not None:
            return {"id": (obj.from_bank_acct.id), "account_num": number_obfuscator(obj.from_bank_acct.account_num)}
        else:
            pass

class ListAllTypesSerializer(serializers.ModelSerializer):


    class Meta:
        model=VendorType
        fields=('id','type')

class ListBankAcctsSerializer(serializers.ModelSerializer):

    class Meta:
        list_serializer_class = FilteredBankListSerializer
        model=BankInformation
        fields=('id', 'account_num')

class ListPaymentMethodsSerializer(serializers.ModelSerializer):

    class Meta:
        model=PaymentMethod
        fields=('id', 'method')

class SaveVendorApproversSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    class Meta:
            model=VendorApprover
            fields=('id', 'above_amount','user')

    def create(self, validated_data):
        preference, created = VendorApprover.objects.update_or_create(
            id=validated_data.get('id'),
            defaults={'companylink': validated_data.get('companylink', None),
                      'above_amount': validated_data.get('above_amount', None)})
        user_list = [user.id for user in validated_data.get('user')]
        users = User.objects.filter(company=validated_data.get('company'), id__in=user_list)
        preference.user.set(users)
        return preference

class DeleteVendorApproverSerializer(serializers.ModelSerializer):

    class Meta:
        model=VendorApprover
        fields=('id', 'is_deleted')

class ListVendorApproverSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    class Meta:
        model=VendorApprover
        fields=('id', 'above_amount', 'user')
        depth=1

class CreateVendorInvoiceSettingsSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    class Meta:
        model=InvoicePreference
        fields=('id', 'companyaccount','acct_class', 'department', 'location', 'term')

class UpdateVendorInvoiceSettingsSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    class Meta:
        model=InvoicePreference
        fields=('id', 'companyaccount', 'acct_class', 'department', 'location', 'term')

class ListVendorInvoiceSettingsSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    class Meta:
        model=InvoicePreference
        fields=('id', 'companyaccount', 'acct_class', 'department', 'location', 'term')

class ListVendorBankAcctInfoSerializer(serializers.ModelSerializer):

    class Meta:
        list_serializer_class = FilteredBankListSerializer
        model=BankInformation
        fields=('id', 'account_num', 'is_default')

class ListVendorInvoicesSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        inv = super().to_representation(instance)
        invoice = Invoice.objects.get(pk=inv['id'])
        inv['amount_remaining'] = "{0:.2f}".format(inv['total']-sum([payment.amount for payment in invoice.payment_set.all()]))
        del inv['total']
        return inv
    class Meta:
        model=Invoice
        fields= ('id', 'invoice_num', 'invoice_date', 'due_date', 'total')

class ListVendorPaymentsSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        pay = super().to_representation(instance)
        pay['status'] = "Paid" if pay['date_payed'] else "In Progress"
        return pay
    payment_method = serializers.SerializerMethodField()
    class Meta:
        model=Payment
        fields=('id', 'date_payed', 'date_to_pay','amount', 'payment_method')

    def get_payment_method(self, obj):
        return (obj.payment_method.method)

class CreateVendorNoteSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        note = super().to_representation(instance)
        del note['user']
        return note
    creator_name = serializers.SerializerMethodField()
    creator_email = serializers.SerializerMethodField()
    class Meta:
        model=Note
        fields=('id', 'note', 'date_added', 'user', 'creator_name', 'creator_email')

    def get_creator_name(self, obj):
        return (obj.user.first_name + " " + obj.user.last_name)

    def get_creator_email(self, obj):
        return (obj.user.email)

class DeleteVendorNoteSerializer(serializers.ModelSerializer):

    class Meta:
        model=Note
        fields=('id', 'is_deleted')

class ListVendorNotesSerializer(serializers.ModelSerializer):
    def to_representation(self, instance):
        note = super().to_representation(instance)
        del note['user']
        return note
    creator_name = serializers.SerializerMethodField()
    creator_email = serializers.SerializerMethodField()
    class Meta:
        model=Note
        fields=('id', 'note', 'date_added', 'user', 'creator_name', 'creator_email')

    def get_creator_name(self, obj):
        return (obj.user.first_name + " " + obj.user.last_name)

    def get_creator_email(self, obj):
        return (obj.user.email)

class UtilityCreateCompanyAccountsSerializer(serializers.ModelSerializer):
    company = serializers.CharField(default=0)
    class Meta:
        model=CompanyAccount
        fields=('name', 'sys_account_id', 'classification', 'is_active', 'balance', 'balancewithsubs', 'type', 'sub_type',
               'currency','parent_account', 'synctoken', 'company', 'account_num')

class UtilityCreateClassSerializer(serializers.ModelSerializer):
    company = serializers.CharField(default=0)
    class Meta:
        model=Class
        fields=('sys_class_id', 'synctoken', 'name', 'company', 'parent_class', 'is_active')

class UtilityCreateDepartmentSerializer(serializers.ModelSerializer):
    company = serializers.CharField(default=0)
    class Meta:
        model=Department
        fields=('sys_department_id', 'synctoken', 'name', 'company', 'parent_department', 'is_active')

class CreateVendorTokenSerializer(serializers.ModelSerializer):

    class Meta:
        model=Token
        fields=('id','company','to_address','vendor_name','token')

class EmailCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model=Email
        fields=('subject','text','to_address','from_address','company','type','token')

class FilteredListOnboardVendorPendingSerializer(serializers.ListSerializer):

    def to_representation(self, data):
        data = data.filter(is_deleted=False, is_used=False).order_by('-date_created')
        return super(FilteredListOnboardVendorPendingSerializer, self).to_representation(data)

class ListOnboardVendorPendingSerializer(serializers.ModelSerializer):
    is_expired = serializers.SerializerMethodField()
    onboard_id = serializers.SerializerMethodField()

    class Meta:
        list_serializer_class = FilteredListOnboardVendorPendingSerializer
        model=Token
        fields=('onboard_id','vendor_name', 'to_address', 'date_created','is_expired')

    def get_is_expired(self, obj):
        time_between_create =  timezone.now() - obj.date_created
        expired = False if time_between_create.days <= 10 else True
        return expired

    def get_onboard_id(self, obj):
        return obj.id

class ListOnboardCompanyPendingSerializer(serializers.ModelSerializer):
    allowed_requests = serializers.SerializerMethodField()
    current_requests = serializers.SerializerMethodField()
    company_id = serializers.SerializerMethodField()
    onboard_data = ListOnboardVendorPendingSerializer(many=True)
    class Meta:
        model=Company
        fields=('company_id','company_name', 'allowed_requests', 'current_requests', 'onboard_data')

    def get_company_id(self, obj):
        return obj.id

    def get_allowed_requests(self, obj):
        request = self.context.get('request')
        return allowed_onboard_req_int(request.user.account.plan.allowed_onboard_requests)

    def get_current_requests(self, obj):
        request = self.context.get('request')
        dates = get_month_first_last_day()
        curr_requests = Token.objects.filter(company__account=request.user.account.id, date_created__range=(dates[0], dates[1]), is_deleted=False).count()
        return curr_requests


class ResendVendorTokenSerializer(serializers.ModelSerializer):

    class Meta:
        model=Token
        fields=('id','company','to_address','vendor_name','token')

class DeleteOnboardVendorRequestSerializer(serializers.ModelSerializer):

    class Meta:
        model=Token
        fields=('id', 'is_deleted')

class HideReceivedVendorOnboardRequestSerializer(serializers.ModelSerializer):

    class Meta:
        model=Token
        fields=('id', 'is_hidden')

class RetrieveOnboardVendorSerializer(serializers.ModelSerializer):
    onboard_id = serializers.SerializerMethodField()
    company_name = serializers.SerializerMethodField()
    term_list = serializers.SerializerMethodField()
    class Meta:
        model=Token
        fields=('onboard_id', 'company', 'vendor_name', 'date_created', 'company_name', 'term_list')

    def get_onboard_id(self, obj):
        return obj.id

    def get_company_name(self, obj):
        return obj.company.company_name

    def get_term_list(self, obj):
        term_query = Term.objects.filter(company=obj.company.id, is_active=True)
        termlist = list(term_query)
        terms = []
        for term in termlist:
            terms.append({"id":term.id, "term":term.term})
        return terms

class SaveOnboardW9DataSerializer(serializers.ModelSerializer):

    class Meta:
        model=TaxForm
        fields = ('name', 'business_name', 'tax_class', 'exemption', 'address', 'location', 'account_numbers', 'tin',
                  'companylink', 'signature', 'year')  # , 'w9_upload', 'signature_upload', 'token')
        extra_kwargs = {
            'name': {'write_only': True},
            'business_name': {'write_only': True},
            'tax_class': {'write_only': True},
            'exemption': {'write_only': True},
            'address': {'write_only': True},
            'location': {'write_only': True},
            'account_numbers': {'write_only': True},
            'tin': {'write_only': True},
            'companylink': {'write_only': True},
            'signature': {'write_only': True},
            'year': {'write_only': True},
        }

class SaveOnboardContactInfoDataSerializer(serializers.ModelSerializer):

    class Meta:
        model = ContactInfo
        fields = ('phone', 'address1', 'city', 'state', 'zip', 'country', 'email', 'title', 'first_name', 'middle_name',
                  'last_name', 'suffix', 'company_name', 'fax', 'mobile', 'companylink')
        validators = [valid_city, valid_state, valid_country]

class SaveOnboardBankInfoDataSerializer(serializers.ModelSerializer):

    class Meta:
        model=BankInformation
        fields=('acctinfo', 'companylink')

class SaveOnboardTermSerializer(serializers.ModelSerializer):

    class Meta:
        model=VendorTerm
        fields=('companylink', 'term')

class SaveOnboardVendorSerializer(serializers.ModelSerializer):

    class Meta:
        model = Vendor
        fields = ('id','company_name')

class ListOnboardVendorContactInfo(serializers.ModelSerializer):

    class Meta:
        model = ContactInfo
        fields = ('phone', 'address1', 'city', 'state', 'zip', 'country', 'email', 'title', 'first_name', 'middle_name',
                  'last_name', 'suffix', 'company_name', 'fax', 'mobile')


class ListOnboardVendorInfoSerializer(serializers.ModelSerializer):

    class Meta:
        model=Vendor
        fields=('company_name',)

class RetrieveOnboardVendorTermSerializer(serializers.ModelSerializer):
    term = serializers.SerializerMethodField()
    class Meta:
        model=VendorTerm
        fields=('id', 'term')

    def get_term(self, obj):
        return obj.term.term

class ListOnboardCompanyLinkSerializer(serializers.ModelSerializer):
    vendordata = ListOnboardVendorInfoSerializer(source='vendor')
    contactinfo = ContactInfoCreateUpdateSerializer(many=True)
    vendor_term = RetrieveOnboardVendorTermSerializer(many=True)
    class Meta:
        model=CompanyLink
        fields=('company', 'vendor', 'vendordata', 'contactinfo', 'vendor_term')

    def to_representation(self, obj):
        """Move fields from vendordata to onboardcompanylink representation."""
        representation = super().to_representation(obj)
        vendor_representation = representation.pop('vendordata')
        contact_representation = representation.pop('contactinfo')[0] if representation.pop('contactinfo') else []
        for key in vendor_representation:
            representation[key] = vendor_representation[key]

        for key in contact_representation:
            representation[key] = contact_representation[key]

        return representation

class FilteredListOnboardVendorReceivedSerializer(serializers.ListSerializer):

    def to_representation(self, data):
        data = data.filter(is_deleted=False, is_used=True, is_hidden=False).order_by('-date_updated')
        return super(FilteredListOnboardVendorReceivedSerializer, self).to_representation(data)

class ListOnboardVendorReceivedSerializer(serializers.ModelSerializer):
    vendor_data=ListOnboardCompanyLinkSerializer(source='companylink')
    onboard_id = serializers.SerializerMethodField()

    class Meta:
        list_serializer_class = FilteredListOnboardVendorReceivedSerializer
        model=Token
        fields=('onboard_id', 'vendor_name', 'to_address', 'date_updated', 'vendor_data')

    def get_onboard_id(self, obj):
        return obj.id

class ListOnboardCompanyReceivedSerializer(serializers.ModelSerializer):
    allowed_requests = serializers.SerializerMethodField()
    current_requests = serializers.SerializerMethodField()
    company_id = serializers.SerializerMethodField()
    onboard_data = ListOnboardVendorReceivedSerializer(many=True)
    class Meta:
        model=Company
        fields=('company_id', 'company_name', 'allowed_requests', 'current_requests', 'onboard_data')

    def get_company_id(self, obj):
        return obj.id

    def get_allowed_requests(self, obj):
        request = self.context.get('request')
        return allowed_onboard_req_int(request.user.account.plan.allowed_onboard_requests)

    def get_current_requests(self, obj):
        request = self.context.get('request')
        dates = get_month_first_last_day()
        curr_requests = Token.objects.filter(company__account=request.user.account.id, date_created__range=(dates[0], dates[1]), is_deleted=False).count()
        return curr_requests

class UtilityTermCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Term
        fields = ('id','sys_term_id', 'term', 'company_id', 'synctoken', 'dayofmonthdue', 'discountdayofmonth',
                  'discountdays', 'discountpercent', 'duedays', 'duenextmonthdays', 'is_active')

    def create(self, validated_data):
        term = Term.objects.create(**validated_data)
        return term

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password_reset_form_class = PasswordResetForm
    def validate_email(self, value):
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(_('Error'))
        return value

    def save(self):
        request = self.context.get('request')
        opts = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_FROM_EMAIL'),
            'subject_template_name': 'password_reset_subject.txt',
            'email_template_name': 'password_reset_email.html',

            'request': request,
        }
        self.reset_form.save(**opts)

class DeactivateAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ('id', 'is_active')

class ReactivateAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ('id', 'is_active', 'plan')

class UpdateCompanyBankInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = BankInformation
        fields = ('id', 'company')

    def validate(self, data):
        acctdata = self.context['request'].data.get('bank', None)
        if acctdata is None:
            raise (serializers.ValidationError({"bank": "This field is required"}))
        if not acctdata.get('account_num') or not acctdata.get('account_num').isnumeric() or len(acctdata.get('account_num')) not in range(4, 17):
            raise (serializers.ValidationError({"account_num": "Invalid account number"}))
        if not acctdata.get('routing_num') or not acctdata.get('routing_num').isnumeric() or len(acctdata.get('routing_num')) not in range(8, 12):
            raise (serializers.ValidationError({"account_num": "Invalid routing number"}))
        return data

    def update(self, instance, validated_data):
        instance.acctinfo = validated_data.get('acctinfo', instance.acctinfo)
        instance.save()
        return instance

class FilteredListOnboardVendorAllSerializer(serializers.ListSerializer):

    def to_representation(self, data):
        data = data.filter(is_deleted=False, is_hidden=False).order_by('is_used', '-date_updated')
        return super(FilteredListOnboardVendorAllSerializer, self).to_representation(data)

class ListOnboardVendorAllSerializer(serializers.ModelSerializer):
    vendor_data=ListOnboardCompanyLinkSerializer(source='companylink')
    is_expired = serializers.SerializerMethodField()
    onboard_id = serializers.SerializerMethodField()

    class Meta:
        list_serializer_class = FilteredListOnboardVendorAllSerializer
        model=Token
        fields=('onboard_id', 'vendor_name', 'to_address', 'date_created', 'date_updated', 'vendor_data', 'is_expired')

    def get_is_expired(self, obj):
        time_between_create = timezone.now() - obj.date_created
        if obj.is_used:
            expired = None
        else:
            expired = False if time_between_create.days <= 10 else True
        return expired

    def get_onboard_id(self, obj):
        return obj.id

class ListOnboardCompanyAllSerializer(serializers.ModelSerializer):
    allowed_requests = serializers.SerializerMethodField()
    current_requests = serializers.SerializerMethodField()
    company_id = serializers.SerializerMethodField()
    onboard_data = ListOnboardVendorAllSerializer(many=True)
    class Meta:
        model=Company
        fields=('company_id', 'company_name', 'allowed_requests', 'current_requests', 'onboard_data')

    def get_company_id(self, obj):
        return obj.id

    def get_allowed_requests(self, obj):
        request = self.context.get('request')
        return allowed_onboard_req_int(request.user.account.plan.allowed_onboard_requests)

    def get_current_requests(self, obj):
        request = self.context.get('request')
        dates = get_month_first_last_day()
        curr_requests = Token.objects.filter(company__account=request.user.account.id, date_created__range=(dates[0], dates[1]), is_deleted=False).count()
        return curr_requests