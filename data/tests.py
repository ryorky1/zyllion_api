# import json
# from django.urls import reverse
# from django.contrib.auth import get_user_model
#
# ZyllionUser = get_user_model()
#
# from rest_framework.test import APITestCase, APIClient
# from rest_framework.views import status
# from .models import Account, PaymentMethod, Plan, Company, Currency, Language, System, TaxForm, Role
# from .serializers import AccountSerializer
# from django.utils import timezone
#
# # tests for models
#
#
# class AccountModelTest(APITestCase):
#     def setUp(self):
#         pm = PaymentMethod(method='Zyllion')
#         pm.save()
#         p = Plan(plan_name='basic', price=99, date_created=timezone.now(), is_active=1, is_displayed=1)
#         p.save()
#         self.a_account = Account.objects.create(
#             # title="Ugandan anthem",
#             # artist="George William Kakoma"
#             company_name="Bob's Burgers", contact_name="Bob", username="bobby", password="So2pv8Xj", is_active=1, payment_method_id=1,
#             is_verified=1, plan_id=1, date_created=timezone.now()
#         )
#
#     def test_account(self):
#         """"
#         This test ensures that the account created in the setup
#         exists
#         """
#         self.assertEqual(self.a_account.company_name, "Bob's Burgers")
#         self.assertEqual(self.a_account.contact_name, "Bob")
#         #self.assertEqual(str(self.a_account), "Ugandan anthem - George William Kakoma")
#
# # tests for views
#
#
# class BaseViewTest(APITestCase):
#     client = APIClient()
#     pm = PaymentMethod(method='Zyllion')
#     pm.save()
#     p = Plan(plan_name='basic', price=99, date_created=timezone.now(), is_active=1, is_displayed=1)
#     p.save()
#     @staticmethod
#     def create_account(company_name="", contact_name="", username="", password="", is_active="", payment_method_id="",
#                        is_verified="", plan_id="", date_created=""):
#         """
#         Create a account in the db
#         :param company_name:
#         :param contact_name:
#         :param username:
#         :param password:
#         :param is_active:
#         :param payment_method_id:
#         :param is_verified:
#         :param plan_id:
#         :param date_created:
#         :return:
#         """
#         if company_name != "" and contact_name != "" and username != "" and password != "" and is_active != "" \
#                 and payment_method_id != "" and is_verified != "" and plan_id != "" and date_created != "":
#             Account.objects.create(company_name=company_name, contact_name=contact_name, username=username,
#                                    password=password, is_active=is_active, is_verified=is_verified, payment_method_id=payment_method_id, plan_id=plan_id, date_created=timezone.now())
#
#     def make_a_request(self, kind="post", **kwargs):
#         """
#         Make a post request to create a account
#         :param kind: HTTP VERB
#         :return:
#         """
#         if kind == "post":
#             return self.client.post(
#                 reverse(
#                     "accounts-list-create",
#                     kwargs={
#                         "version": kwargs["version"]
#                     }
#                 ),
#                 data=json.dumps(kwargs["data"]),
#                 content_type='application/json'
#             )
#         elif kind == "put":
#             return self.client.put(
#                 reverse(
#                     "accounts-detail",
#                     kwargs={
#                         "version": kwargs["version"],
#                         "pk": kwargs["id"]
#                     }
#                 ),
#                 data=json.dumps(kwargs["data"]),
#                 content_type='application/json'
#             )
#         else:
#             return None
#
#     def fetch_a_account(self, pk=0):
#         return self.client.get(
#             reverse(
#                 "accounts-detail",
#                 kwargs={
#                     "version": "v1",
#                     "pk": pk
#                 }
#             )
#         )
#
#     def delete_a_account(self, pk=1):
#         return self.client.delete(
#             reverse(
#                 "accounts-detail",
#                 kwargs={
#                     "version": "v1",
#                     "pk": pk
#                 }
#             )
#         )
#
#     def login_a_user(self, username="", password=""):
#         url = reverse(
#             "auth-login",
#             kwargs={
#                 "version": "v1"
#             }
#         )
#         return self.client.post(
#             url,
#             data=json.dumps({
#                 "username": username,
#                 "password": password
#             }),
#             content_type="application/json"
#         )
#
#     def login_client(self, username="", password=""):
#         # get a token from DRF
#         response = self.client.post(
#             reverse("create-token"),
#             data=json.dumps(
#                 {
#                     'username': username,
#                     'password': password
#                 }
#             ),
#             content_type='application/json'
#         )
#         self.token = response.data['token']
#         # set the token in the header
#         self.client.credentials(
#             HTTP_AUTHORIZATION='Bearer ' + self.token
#         )
#         self.client.login(username=username, password=password)
#         return self.token
#
#     def register_a_user(self, username="", password="", email=""):
#         return self.client.post(
#             reverse(
#                 "auth-register",
#                 kwargs={
#                     "version": "v1"
#                 }
#             ),
#             data=json.dumps(
#                 {
#                     "username": username,
#                     "password": password,
#                     "email": email
#                 }
#             ),
#             content_type='application/json'
#         )
#
#     def setUp(self):
#         # client = APIClient()
#         # pm = PaymentMethod(id=1, method='Zyllion')
#         # pm.save()
#         # p = Plan(id=1, plan_name='basic', price=99, date_created=timezone.now(), is_active=1, is_displayed=1)
#         # p.save()
#         # a = Account(id=1, company_name="Test Company", contact_name="TestName", username="test", password="So2pv8Xj",
#         #             is_active=True, is_verified=True, payment_method_id=1, plan_id=1, date_created=timezone.now())
#         # a.save()
#         # cu = Currency(id=1, currency_name="Dollar")
#         # cu.save()
#         # l = Language(id=1, name="English")
#         # l.save()
#         # s = System(id=1, name="Quickbooks")
#         # s.save()
#         # t = TaxForm(id=1, name="Test Name", business_name="Test Business Name", tax_class="A1", exemption_code="1234", address="1234 Test Street", city_state_zip='{"city":"Nashville", "state":"TN", "zip":"12345"}', account_nums="", requestor_info="", signature_url="", date=timezone.now())
#         # t.save()
#         # c=Company(id=1, sys_company_id=1, parent=None, company_name='Jans Diner', ap_email="ap.jansdiner@zyllion.co",
#         #           ar_email="ar.jansdiner@zyllion.co", email="jansdiner@janco.com", is_partner=True,
#         #           date_created=timezone.now(), date_updated=timezone.now(), account_id=1, currency_id=1, language_id=1,
#         #           system_id=1, taxform_id=1)
#         # c.save()
#         r = Role(id=1, role_name="Admin", role_type="User")
#         r.save()
#         # create a admin user
#         # self.user = ZyllionUser.objects.create_user(
#         #     username="test_user",
#         #     email="test@mail.com",
#         #     password="testing",
#         #     first_name="test",
#         #     last_name="user",
#         # )
#         # add test data
#         self.create_account('test company', 'joe', 'ryorky1', 'So2pv8Xj', 1, 1, pm, p)
#         self.create_account("simple song", "konshens", 'ryorky2', 'So2pv8Xj', 1, 1, pm, p)
#         self.create_account("love is wicked", "brick and lace", 'ryorky3', 'So2pv8Xj', 1, 1, pm, p)
#         self.create_account("jam rock", "damien marley", 'ryorky4', 'So2pv8Xj', 1, 1, pm, p)
#         self.valid_data = {
#             "company_name": "test account",
#             "contact_name": "test artist",
#             "username": "username",
#             "password": "password",
#             "is_active": True,
#             "is_verified": True,
#             "payment_method_id": 1,
#             "plan_id": 1,
#             # fix timezone
#             #currently returns
#             "date_created": ""
#
#         }
#         self.invalid_data = {
#             "company_name": "",
#             "contact_name": ""
#         }
#         self.valid_account_id = 1
#         self.invalid_account_id = 100
#
#
# class AddAccountTest(BaseViewTest):
#
#     def test_create_a_account(self):
#         del self.valid_data["date_created"]
#         print(self.valid_data)
#         """
#         This test ensures that a single account can be added
#         """
#         self.login_client('test_user', 'testing')
#         # hit the API endpoint
#         response = self.make_a_request(
#             kind="post",
#             version="v1",
#             data=self.valid_data
#         )
#         del response.data["date_created"]
#         print(response.data)
#         self.assertEqual(response.data, self.valid_data)
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         # test with invalid data
#         response = self.make_a_request(
#             kind="post",
#             version="v1",
#             data=self.invalid_data
#         )
#         self.assertEqual(
#             response.data["message"],
#             "Both title and artist are required to add a account"
#         )
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
#
# class AuthRegisterZyllionUserTest(BaseViewTest):
#     """
#     Tests for auth/register/ endpoint
#     """
#     def test_register_a_user(self):
#         response = self.register_a_user("new_user", "new_pass", "new_user@mail.com")
#         # assert status code is 201 CREATED
#         self.assertEqual(response.data["username"], "new_user")
#         self.assertEqual(response.data["email"], "new_user@mail.com")
#         self.assertEqual(response.status_code, status.HTTP_201_CREATED)
#         # test with invalid data
#         response = self.register_a_user()
#         # assert status code
#         self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)