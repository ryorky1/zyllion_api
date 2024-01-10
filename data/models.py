# @property
# @staticmethod
# @classmethod
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
import uuid, datetime
from django.conf import settings
from django.contrib.auth.models import PermissionsMixin
from django.core.mail import send_mail
from django.db.models import Q, Count

def jwt_get_secret_key(user_model):
    return user_model.jwt_secret

class Plan(models.Model):
    plan_name = models.CharField(max_length=50)
    plan_text = models.TextField()
    price = models.CharField(max_length=25)
    date_created = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField()
    is_displayed = models.BooleanField()
    allowed_users = models.CharField(max_length=10)
    per_user = models.FloatField(null=True)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True)
    allowed_onboard_requests = models.CharField(max_length=25, null=True)
    description = models.CharField(max_length=255, null=True)
    base_price = models.FloatField(null=True)
    stripe_plan_id = models.CharField(max_length=100, null=True)

    def __str__(self):
        return self.plan_name

class PaymentMethod(models.Model):
    method = models.CharField(max_length=15)
    is_zyllion_default = models.BooleanField(default=True)

    def __str__(self):
        return self.method

class System(models.Model):
    name = models.CharField(max_length=75)
    plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.name

class Account(models.Model):
    class Meta:
        permissions = (
            ('modify_account','Can update or cancel an account'),
        )
    company_name = models.CharField(max_length=100, blank=False)
    contact_name = models.CharField(max_length=50, blank=False)
    is_active = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    plan = models.ForeignKey(Plan, on_delete=models.SET_NULL, null=True, blank=False)
    num_users = models.IntegerField(blank=False)
    date_created = models.DateTimeField(auto_now_add=True)
    ap_email = models.EmailField(max_length=200, blank=True, null=True)
    ar_email = models.EmailField(max_length=200, blank=True, null=True)
    system = models.ForeignKey(System, on_delete=models.SET_NULL, blank=True, null=True)
    date_updated = models.DateTimeField(auto_now=True)
    stripe_cust_token = models.CharField(max_length=75, null=True)

    def __str__(self):
        return self.company_name

class QBToken(models.Model):
    account = models.OneToOneField(Account, on_delete=models.SET_NULL, null=True)
    realm_id = models.TextField()
    access_token = models.TextField()
    refresh_token = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)

    def  __str__(self):
        return self.account


class AccountPlanLog(models.Model):
    date_changed = models.DateTimeField(auto_now_add=True)
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, default=1)
    user = models.IntegerField(blank=False, default=5)

    def __str__(self):
        return self.account

class Language(models.Model):
    name = models.CharField(max_length=25)

class Currency(models.Model):
    name = models.CharField(max_length=25)

class CompanyType(models.Model):
    name = models.CharField(max_length=2)

class Company(models.Model):
    sys_company_id = models.CharField(max_length=75, blank=True, null=True)
    synctoken = models.CharField(max_length=75, null=True)
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, blank=True)
    company_name = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    language = models.ForeignKey(Language, on_delete=models.SET_NULL, null=True, blank=True)
    currency = models.ForeignKey(Currency, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.company_name

class Customer(models.Model):
    sys_customer_id = models.CharField(max_length=75, blank=True, null=True)
    synctoken = models.CharField(max_length=75, null=True)
    company_name = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    language = models.ForeignKey(Language, on_delete=models.SET_NULL, null=True, blank=True)
    currency = models.ForeignKey(Currency, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.company_name

class Vendor(models.Model):
    sys_vendor_id = models.CharField(max_length=75, blank=True, null=True)
    synctoken = models.CharField(max_length=75, null=True)
    company_name = models.CharField(max_length=100, null=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    language = models.ForeignKey(Language, on_delete=models.SET_NULL, null=True, blank=True)
    currency = models.ForeignKey(Currency, on_delete=models.SET_NULL, null=True, blank=True)
    #added for updating onboarded vendors
    is_1099 = models.BooleanField(default=False)
    assoc_acct = models.CharField(max_length=100, null=True)
    check_name = models.CharField(max_length=100, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.company_name

class CompanyLink(models.Model):
    company = models.ForeignKey(Company, related_name='company', on_delete=models.SET_NULL, null=True)
    customer = models.ForeignKey(Customer, related_name='customer', on_delete=models.SET_NULL, null=True)
    vendor = models.ForeignKey(Vendor, related_name='vendor', on_delete=models.SET_NULL, null=True)
    linked_company = models.ForeignKey(Company, related_name='linked_company', on_delete=models.SET_NULL, null=True)
    is_link_accepted = models.BooleanField(default=False)
    date_created = models.DateTimeField(auto_now_add=True)
    date_accepted = models.DateTimeField(null=True)

    def __str__(self):
        return str(self.company)

class Token(models.Model):
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, related_name="onboard_data")
    #user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)  #for when email needs to be sent to user who forgets password
    to_address = models.EmailField(max_length=200)
    vendor_name = models.CharField(max_length=75)
    token = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    is_used = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)
    is_hidden = models.BooleanField(default=False)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)

    def __str__(self):
        return self.vendor_name

class TaxForm(models.Model):
    name = models.CharField(max_length=100)
    business_name = models.CharField(max_length=100, null=True)
    tax_class = JSONField()
    exemption = JSONField(null=True)
    address = models.CharField(max_length=100)
    location = models.CharField(max_length=200)
    account_numbers = models.TextField(null=True)
    tin = JSONField()
    #w9_upload = models.FileField(blank=False, null=False)
    #signature_upload = models.FileField(blank=True, null=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    is_deleted = models.BooleanField(default=False)
    signature = models.TextField()
    year = models.CharField(max_length=4)

    def __unicode__(self):
        return self.business_name

class BankInformation(models.Model):
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, related_name='bankinfo')
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    acctinfo = JSONField()
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    is_default = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return str(self.acctinfo)

#include link to email table to track when sent???
class LinkRequest(models.Model):
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    requestlink = models.CharField(max_length=255)
    date_created = models.DateTimeField(auto_now_add=True)
    date_accepted = models.DateTimeField(auto_now=True)
    is_accepted = models.BooleanField(default=False)

    def __str__(self):
        return str(self.companylink)


class Status(models.Model):
    status = models.CharField(max_length=25)
    status_text = models.CharField(max_length=25)
    type = models.CharField(max_length=2)

    def __str__(self):
        return self.status

class Po(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_po_id', 'companylink')

    sys_po_id = models.CharField(max_length=75)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    po_upload = models.FileField(blank=False, null=False)
    created_date = models.DateTimeField()
    received_date = models.DateTimeField()

    def __str__(self):
        return self.created_date


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)
    #Allow Users to log in with case insensitive email addresses
    def get_by_natural_key(self, username):
        case_insensitive_username_field = '{}__iexact'.format(self.model.USERNAME_FIELD)
        return self.get(**{case_insensitive_username_field: username})

class User(AbstractBaseUser, PermissionsMixin):
    class Meta:
        verbose_name = 'user'
        verbose_name_plural = 'users'
        permissions = (
            ('create_any_user', 'Can create any company user'),
            ('create_manager_user', 'Can create manager users and below'),
            ('edit_any_user', 'Can update any user'),
            ('edit_manager_user', 'Can edit manager users and below'),
            ('edit_own_user', 'Can edit own user')
        )
    company = models.ManyToManyField(Company, blank=True)
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, blank=True, null=True)
    first_name = models.CharField(max_length=25)
    last_name = models.CharField(max_length=25)
    email = models.EmailField(verbose_name='email address', max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    jwt_secret = models.UUIDField(default=uuid.uuid4)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def get_full_name(self):
        '''
        Returns the first_name plus the last_name, with a space in between.
        '''
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        '''
        Returns the short name for the user.
        '''
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        '''
        Sends an email to this User.
        '''
        send_mail(subject, message, from_email, [self.email], **kwargs)

class UserLog(models.Model):
    date_changed = models.DateTimeField(auto_now_add=True)
    modifier = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='modifier', blank=True, null=True)
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, blank=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='user', null=True)
    action = models.CharField(max_length=25)

    def __str__(self):
        return self.account

class Term(models.Model):
    #
    #
    # class Meta:
    #     unique_together = ('sys_term_id', 'company')

    sys_term_id = models.CharField(max_length=75)#possibly remove
    synctoken = models.CharField(max_length=75, null=True)#possibly remove
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, blank=True, null=True)#possibly remove
    term = models.CharField(max_length=25)
    discountpercent = models.FloatField(max_length=5, null=True)
    discountdays = models.IntegerField(null=True)
    is_active = models.BooleanField(default=True)
    # type = models.CharField(max_length=50, null=True)
    dayofmonthdue = models.IntegerField(null=True)
    discountdayofmonth = models.IntegerField(null=True)
    duenextmonthdays = models.IntegerField(null=True)
    duedays = models.IntegerField(null=True)

    def __str__(self):
        return self.term

class VendorTerm(models.Model):
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True, blank=False, related_name='vendor_term')
    term = models.ForeignKey(Term, on_delete=models.SET_NULL, null=True, blank=False)

# class ApAccount(models.Model):
#     sys_apaccount_id = models.CharField(max_length=75)
#     company = models.ForeignKey(Company, on_delete=models.CASCADE)
#     name = models.CharField(max_length=75)
#
#     def __str__(self):
#         return self.name
#
# class GlAccount(models.Model):
#     sys_glaccount_id = models.CharField(max_length=75)
#     company = models.ForeignKey(Company, on_delete=models.CASCADE)
#     name= models.CharField(max_length=75)
#
#     def __str__(self):
#         return self.name
#
class Class(models.Model):

    class Meta:
        unique_together = ('sys_class_id', 'company')

    sys_class_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    name= models.CharField(max_length=75)
    parent_class = models.CharField(max_length=25, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class CompanyAccount(models.Model):

    class Meta:
        unique_together = ('sys_account_id', 'company')

    sys_account_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=75)
    account_num = models.CharField(max_length=10, null=True)
    classification = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    parent_account = models.CharField(max_length=25, null=True)
    currency = models.TextField(max_length=25)
    balance = models.FloatField(null=True, default=0.00)
    balancewithsubs = models.FloatField(null=True, default=0.00)
    type = models.CharField(max_length=50)
    sub_type = models.CharField(max_length=50)

    def __str__(self):
        return self.name

class Department(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_department_id', 'company')

    sys_department_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    name= models.CharField(max_length=75)
    parent_department = models.CharField(max_length=25, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name

class Location(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_location_id', 'company')

    sys_location_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    name= models.CharField(max_length=75)


    def __str__(self):
        return self.name


class VendorType(models.Model):
    type = models.CharField(max_length=50)

    def __str__(self):
        return self.type

class PaymentPreference(models.Model):
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    send_remittance_email = models.BooleanField(default=False)
    from_bank_acct = models.ForeignKey(BankInformation, on_delete=models.SET_NULL, blank=True, null=True, related_name='fromacct')

    def __str__(self):
        return self.companylink.vendor.company_name

class PaymentOption(models.Model):
    paymentpreference = models.ForeignKey(PaymentPreference, on_delete=models.SET_NULL, null=True, related_name='paymentpreference')
    paymentmethod = models.ForeignKey(PaymentMethod, on_delete=models.SET_NULL, blank=True, null=True, related_name='paymentmethod')
    is_default = models.BooleanField(default=False)
    is_enabled = models.BooleanField(default=False)
    to_bank_acct = models.ForeignKey(BankInformation, on_delete=models.SET_NULL, blank=True, null=True, related_name='toacct', default=None)
    vendor_type = models.ForeignKey(VendorType, on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        return self.paymentmethod.method



class InvoicePreference(models.Model):
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    #expenseacct = models.ForeignKey(CompanyAccount, on_delete=models.SET_NULL, blank=True, null=True, related_name='expenseacct')
    #apaccount = models.ForeignKey(CompanyAccount, on_delete=models.SET_NULL, blank=True, null=True, related_name='apacct')
    companyaccount = models.ForeignKey(CompanyAccount, on_delete=models.SET_NULL, null=True)
    acct_class = models.ForeignKey(Class, on_delete=models.SET_NULL, blank=True, null=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, blank=True, null=True)
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, blank=True, null=True)
    term = models.ForeignKey(Term, on_delete=models.SET_NULL, blank=True, null=True)

    def __str__(self):
        return self.companylink.vendor.company_name

class InvoiceManager(models.Manager):


    def manager_open_invoices_type(self, compids):

        manager_open_count = Invoice.objects.aggregate(
            received=Count('pk', filter=Q(status__status="Received") & Q(status__type="AP"), buyer=compids),
            pending_approval=Count('pk', filter=Q(status__status="Pending Approval") & Q(status__type="AP"), buyer=compids),
            rejected=Count('pk', filter=Q(status__status="Rejected") & Q(status__type="AP"), buyer=compids),
            approved=Count('pk', filter=Q(status__status="Approved") & Q(status__type="AP"), buyer=compids),
            partial_payment=Count('pk', filter=Q(status__status="Partial Payment") & Q(status__type="AP"), buyer=compids),
            allopen=Count('pk', filter=~Q(status__status="Paid") & Q(status__type="AP"), buyer=compids),
        )
        return manager_open_count

class Invoice(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_invoice_id', 'companylink')

    sys_invoice_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    invoice_num = models.CharField(max_length=25)
    invoice_upload = models.FileField(blank=False, null=False)#localtion of physical invoice
    term = models.ForeignKey(Term, on_delete=models.SET_NULL, blank=True, null=True)
    invoice_date = models.DateField()
    #location = models.CharField(max_length=25, blank=True, null=True)# update this for quickbooks, Intacct, etc
    memo = models.CharField(max_length=255, blank=True, null=True)
    created_date = models.DateTimeField(auto_now_add=True)
    updated_date = models.DateTimeField(auto_now=True)
    received_date = models.DateField()
    due_date = models.DateField()
    status = models.ForeignKey(Status, on_delete=models.SET_NULL, null=True)
    subtotal = models.FloatField()
    shipping = models.FloatField()
    other = models.FloatField()
    tax = models.FloatField()
    total = models.FloatField()
    is_deleted = models.BooleanField(default=False)
    companyaccount = models.ForeignKey(CompanyAccount, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank
    acct_class = models.ForeignKey(Class, on_delete=models.SET_NULL, null=True, blank=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank  ### add back in
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank  ### add back in
    objects = InvoiceManager()

    def __str__(self):
        return self.invoice_num

class Credit(models.Model):
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True)
    initial_amount = models.FloatField()
    remaining_amount = models.FloatField()

    def __str__(self):
        return self.invoice

class InvoiceLog(models.Model):
    date_changed = models.DateTimeField(auto_now_add=True)
    modifier = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='invlog_modifier', blank=True, null=True)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True, blank=False)
    status = models.ForeignKey(Status, on_delete=models.SET_NULL, null=True, blank=False)
    action = models.CharField(max_length=25)

    def __str__(self):
        return self.account

class ContactInfo(models.Model):
    sys_company_contactinfo_id = models.CharField(max_length=75, null=True)
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True, related_name='contactinfo')
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True, related_name='contactinfo')
    customer = models.ForeignKey(Customer, on_delete=models.SET_NULL, null=True, related_name='contactinfo')
    vendor = models.ForeignKey(Vendor, on_delete=models.SET_NULL, null=True, related_name='contactinfo')
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True, related_name='contactinfo')
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True)
    po = models.ForeignKey(Po, on_delete=models.SET_NULL, null=True)
    phone = models.CharField(max_length=30, blank=True, null=True)#used for quickbooks
    ext = models.CharField(max_length=15, blank=True, null=True)
    address1 = models.TextField(max_length=None, blank=True, null=True) #is remittance_address for token, quickbooks only has 1 address field, multiple lines
    address2 = models.CharField(max_length=25, blank=True, null=True)
    city = models.CharField(max_length=58, blank=True, null=True)
    state = models.CharField(max_length=20, blank=True, null=True)
    zip = models.CharField(max_length=15, blank=True, null=True)
    country = models.CharField(max_length=30, blank=True, null=True)
    email = models.EmailField(max_length=100, blank=True, null=True)
    #used to store quickbooks data
    title = models.CharField(max_length=15,null=True)
    first_name = models.CharField(max_length=25,null=True)
    middle_name = models.CharField(max_length=25,null=True)
    last_name = models.CharField(max_length=100,null=True)
    suffix = models.CharField(max_length=10,null=True)
    company_name = models.CharField(max_length=100,null=True)
    fax = models.CharField(max_length=30,null=True)
    mobile = models.CharField(max_length=30,null=True)
    #qbaddressdata
    company_address = JSONField(null=True, blank=True)
    legal_address = JSONField(null=True, blank=True)
    cust_comm_address = JSONField(null=True, blank=True)
    billing_address = JSONField(null=True, blank=True)


    def __str__(self):
        return self.email

class ZyllionPayment(models.Model):
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True)
    payment_method = models.ForeignKey(PaymentMethod, on_delete=models.SET_NULL, null=True)
    amount = models.FloatField()
    payment_date = models.DateTimeField()
    approved = models.BooleanField()

    def __str__(self):
        return str(self.payment_date)

class Payment(models.Model):
    #
    class Meta:
        # unique_together = ('sys_payment_id', 'companylink')
        permissions = (
            ('process_payments', 'Can process payments'),
        )
    sys_payment_id = models.CharField(max_length=75, null=True)
    synctoken = models.CharField(max_length=75, null=True)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True)
    payment_method = models.ForeignKey(PaymentMethod, on_delete=models.SET_NULL, null=True)
    amount = models.FloatField()
    reference = models.CharField(max_length=15, null=True)
    date_to_pay = models.DateField()
    date_payed = models.DateField(blank=True, null=True)
    is_processed = models.BooleanField()

    def __str__(self):
        return self.reference


class Note(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_note_id', 'companylink')

    sys_note_id = models.CharField(max_length=75, null=True)
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    #customer = models.ForeignKey(Customer, on_delete=models.CASCADE, null=True)
    po = models.ForeignKey(Po, on_delete=models.SET_NULL, null=True)
    note = models.TextField(max_length=None)
    date_added = models.DateTimeField(auto_now_add=True)
    is_deleted=models.BooleanField(default=False)
    user = models.ForeignKey(User, models.SET_NULL, null=True)

    def __str__(self):
        return self.note

class Approver(models.Model):
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True)
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    date_approved = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField()

    def __unicode__(self):
        return self.approver

class Decliner(models.Model):
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, null=True)
    decliner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    date_declined=models.DateTimeField(auto_now_add=True)
    note = models.ForeignKey(Note, on_delete=models.SET_NULL, null=True)

    def __unicode__(self):
        return self.decliner

class InvoiceLine(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_invoiceline_id', 'invoice')

    sys_invoiceline_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    invoice = models.ForeignKey(Invoice, on_delete=models.SET_NULL, blank=True, null=True, related_name='invoicelines')
    #invoice_num = models.CharField(max_length=25)
    product_number = models.CharField(max_length=25)
    description = models.CharField(max_length=100)
    qty = models.CharField(max_length=20)
    unit_price = models.FloatField()
    line_tax = models.FloatField()
    line_total = models.FloatField()
    # subtotal = models.FloatField()
    # tax = models.FloatField()
    # shipping = models.FloatField()
    # other = models.FloatField()
    # total = models.FloatField()
    # amount_paid = models.FloatField()
    # balance_due = models.FloatField()
    # discount = models.FloatField()
    # payment_terms = models.CharField(max_length=75)
    # date_due = models.DateField()
    companyaccount = models.ForeignKey(CompanyAccount, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank
    acct_class = models.ForeignKey(Class, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank  ### add back in
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank  ### add back in
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True) #remove null and blank  ### add back in
    is_deleted=models.BooleanField(default=False)

    def __str__(self):
        return self.description

class VendorApprover(models.Model):
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    above_amount = models.FloatField()
    user = models.ManyToManyField(User)
    is_deleted = models.BooleanField(default=False)
    tier_id = models.CharField(max_length=5, null=True)

    def __str__(self):
        return str(self.above_amount)

class EmailType(models.Model):
    type = models.CharField(max_length=75)

    def __str__(self):
        return self.type

class Email(models.Model):
    parent = models.IntegerField(null=True)
    subject = models.CharField(max_length=75)
    text = models.TextField(max_length=None)
    to_address = models.EmailField(max_length=200)
    from_address = models.EmailField(max_length=200)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    account = models.ForeignKey(Account, on_delete=models.SET_NULL, null=True)
    type = models.ForeignKey(EmailType, on_delete=models.SET_NULL, null=True)
    token = models.ForeignKey(Token, on_delete=models.SET_NULL, null=True, related_name="onboardemail")
    date_sent = models.DateTimeField(auto_now_add=True)
    date_received = models.DateTimeField(auto_now_add=True)
    is_processed = models.BooleanField(default=False)
    is_failed = models.BooleanField(default=False)

    def __str__(self):
        return self.subject

class Attachment(models.Model):
    email = models.ForeignKey(Email, on_delete=models.SET_NULL, null=True)
    attachment_name = models.CharField(max_length=50)
    attachment_upload = models.FileField(blank=False, null=False)

    def __str__(self):
        return self.attachment_name

class PoLine(models.Model):
    #
    # class Meta:
    #     unique_together = ('sys_poline_id', 'po')

    sys_poline_id = models.CharField(max_length=75)
    synctoken = models.CharField(max_length=75, null=True)
    po = models.ForeignKey(Po, on_delete=models.SET_NULL, null=True)
    po_num = models.CharField(max_length=50)
    product = models.CharField(max_length=50)
    description = models.CharField(max_length=100)
    qty = models.CharField(max_length=20)
    unit_price = models.FloatField()
    line_total = models.FloatField()
    subtotal = models.FloatField()
    tax = models.FloatField()
    shipping = models.FloatField()
    other = models.FloatField()
    total = models.FloatField()
    discount = models.FloatField()

    def __str__(self):
        return self.description

class File(models.Model):
    sys_attachment_id = models.CharField(max_length=75, null=True)
    type = models.CharField(max_length=15)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    company = models.ForeignKey(Company, on_delete=models.SET_NULL, null=True)
    companylink = models.ForeignKey(CompanyLink, on_delete=models.SET_NULL, null=True)