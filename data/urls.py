from django.urls import path, re_path
from rest_framework_jwt import views as jwt_views
from rest_auth.views import (
    PasswordResetView, PasswordResetConfirmView
)
from data import views


urlpatterns = [
    path('account/create', views.AccountUserCreateView.as_view(), name='account-user-create'),
    #list all plans for signup
    path('plans/list', views.PlanListView.as_view(), name='list-all-plans'),
    #list plans based on plan type(i.e. onboarding, ar, ap, all)
    path('plans/list/<parentplan>', views.PlanListView.as_view(), name='list plans pased on '),
    #log out a user on all devices(i.e. kill JWT token)
    path('user/logout/all', views.UserLogoutAllView.as_view(), name='user-logout-all'),

    # Views are defined in Rest Framework JWT, but we're assigning custom paths.
    ## User login
    path('user/login', views.UserLoginView.as_view(), name='user-login'),
    ## Refresh jwt token
    path('user/login/refresh', views.UserRefreshTokenView.as_view(), name='user-login-refresh'),
    ## Retrieve Account, ContactInfo data for account update  contains information for the menubar as well as
    path('account/detaildata', views.AccountDetailView.as_view(), name='account-update-data'),
    ##update Account ContactInfo/Plan
    path('account/updateall', views.AccountUpdateAllView.as_view(), name='account-update-all'),
    ##update Account Info Only, no plan/pricing information included
    path('account/updateinfo', views.AccountUpdateInfoView.as_view(), name='account-update-account'),
    ##Update Account Plan Only, no contact Info
    path('account/updateplan', views.AccountUpdatePlanView.as_view(), name='account-update-plan'),
    ##Update Card for Account
    path('account/updatecard', views.AccountCardUpdateView.as_view(), name='account-update-card'),
    ##Cancel Account and Subscription(i.e. deactivate)
    path('account/cancel', views.AccountDeactivateView.as_view(), name='account-cancel-subscription'),
    ##Reactivate Account
    path('account/reactivate', views.ReactivateAccountView.as_view(), name='account-reactivate'),
    ##check for valid email addresses
    path('user/emailcheck/<email>', views.EmailCheckView.as_view(), name='user-email-check'),

    ###Only Ever used in dev to create companies/businesses
    ##create a new company
    path('company/create', views.CompanyCreateView.as_view(), name='company-create'),
    ## create a self contained customer a company works with
    path('customer/create', views.CustomerCreateView.as_view(), name='customer-create'),
    ## create a self contained vendor a company works with only for dev purposes
    path('vendor/create', views.VendorCreateView.as_view(), name='vendor-create'),
    ###End

    ##update/delete Company
    path('company/update', views.CompanyUpdateView.as_view(), name='company-update'),
    ##update/delete Customer
    path('customer/update', views.CustomerUpdateView.as_view(), name='customer-update'),
    ##update/delete Vendor
    path('vendor/update', views.VendorUpdateView.as_view(), name='vendor-update'),
    ##list systems based off of plan signed up for
    path('account/systems', views.ListSystemView.as_view(), name='list-systems'),
    ##create a new user for the company
    path('user/create', views.UserCreateView.as_view(), name='create-user'),
    ##allow an existin user to update their own information
    path('user/update', views.UserUpdateView.as_view(), name='update-user'),
    ##update an admin/manager to update a users information
    path('admin/userupdate', views.UserAdminUpdateView.as_view(), name='admin-update-user'),
    ##deactivate/activate a user
    path('user/updatestatus', views.UserStatusUpdateView.as_view(), name='delete-user'),
    ##update password
    path('user/password/update', views.ChangePasswordView.as_view(), name='change-password'),
    ##list view for displaying a users information and its group information

    #empty route required for rest-auth password reset to work with drf
    path('password-reset/<uidb64>/<token>/', views.EmptyPasswordResetView.as_view(), name='password_reset_confirm'),
    #password reset email
    path('password/reset', PasswordResetView.as_view(), name='rest_password_reset'),
    #password reset confirmation(actually reset password0
    path('password/reset/confirm', PasswordResetConfirmView.as_view(), name='rest_password_reset_confirm'),
    ##list all users for a company based on role without searching via a specific company(for acctadmins only)
    path('user/list', views.ListCompanyUsersView.as_view(), name='list-company-users'),
    ##list all users for a company based on role
    path('user/list/<companyid>', views.ListCompanyUsersView.as_view(), name='list-company-users2'),
    ##list individual user information for updating own user information
    path('user/display', views.DisplayUserView.as_view(), name='list-user'),
    ##list individual user information for updating user information via admin interface
    path('user/display/<userid>', views.DisplayUserView.as_view(), name='admin-list-user'),
    ##list all available groups a user can be added to when creating or updating based off on logged in user permission
    path('user/availablegroups', views.ListAvailableUserGroupsView.as_view(), name='admin-list-user-groups'),
    ##list all available companies a user can be added to when creating or updating
    path('user/availablecompanies', views.ListAvailableCompaniesView.as_view(), name='admin-list-companies'),
    ##list of companies a user can select from after logging in
    path('app/companyselector', views.ChooseCompanyView.as_view(), name='select-company'),
    ##all information required for app menubar
    path('app/menubar', views.AppMenuBarDataView.as_view(), name='app-menubar-data'),
    ##to determine if setup has been completed.  If not they should be rerouted to the setup pages
    path('app/setupcompleted', views.SetupRequiredView.as_view(), name='setup-required'),
    ##determine if a companies setup is complete
    path('app/compsetupstatus/<companyid>', views.CompanySetupStatusView.as_view(), name='setup-w9-bank-completed'),
    ##return information to determine if setup is complete, company is_active, and number of registered users vs number of allowed users
    path('app/account/datacheck', views.AccountStatus.as_view(), name='account-status'),
    ##list of the companies that will be used in setup for the bankacct, wallet, and w-9 steps
    path('setup/companylist', views.SetupCompanyListView.as_view(), name='setup-company-list'),
    ##create bank account information entrty for a company
    path('setup/bank/create', views.SetupCreateBankView.as_view(), name='create-bank'),
    ##update bank account information entrty for a company
    path('setup/bank/update', views.SetupUpdateBankView.as_view(), name='update-bank'),
    ##list bank account information for a company
    path('setup/bank/list/<company>', views.SetupListBankView.as_view(), name='view-bank'),
    ##********add in this route to upload w9 forms
    path('setup/taxform/upload', views.SetupUploadw9View.as_view(), name='upload-w9'),
    # ##create w9 by for a company by entering it's text
    # path('setup/w9/create', views.SetupCreatew9View.as_view(), name='create-w9'),
    ##update w9 information for a company
    #path('setup/taxform/update',views.SetupUpdatew9View.as_view(), name='update-w9'),
    ##display w-9 text or pdf for review
    path('setup/taxform/display/<cid>', views.SetupDisplayw9View.as_view(), name='display-w9'),
    ##check if ap/ar email check is valid
    path('setup/aparemailcheck/<aparemail>', views.SetupApArEmailCheck.as_view(), name='apar-emailcheck'),
    ##create the ap and/or ar emails
    path('setup/email/create', views.SetupCreateEmails.as_view(), name='apar-email-create'),
    #saves the system to be synced to in the accts table
    path('setup/sync/system/save', views.SetupSaveSystemsView.as_view(), name='system-save'),
    #list ap invoice chart information for default app login page for users/managers
    path('app/ap/overdueinvoicechart/<company>', views.APUserManagerInvoiceChart.as_view(), name='ap-invoice-chart'),
    #list ap invoice chart information for default app login page(meant for switching between user/manager pages)
    # 1 for user 2 for manager(admin pulls from payments) **possibly restrict what they can view
    #Don't use right now
    path('app/ap/overdueinvoicechart/<company>/<role>', views.APUserManagerInvoiceChart.as_view(), name='ap-invoice-chart'),
    #list open invoices for managers by type regardless of whether they are overdue or not
    path('app/ap/openinvoiceschart/<company>', views.APManagerOpenInvoiceChart.as_view(), name='ap-manager-open-invoices'),
    #list total amount of unpaind, pending, and credits
    ##todopath()
    #list invoice statuses for the dashboard unpaid sidebar dropdown filter
    path('app/ap/unpaidsidebarstatuslist', views.APUnpaidStatusListView.as_view(), name='ap-unpaid-status-list'),
    #list invoices statuses for the invoice page status dropdown filter
    path('app/ap/invoicestatusfilterlist', views.APInvoiceStatusListView.as_view(), name='ap-invoice-page-status-list'),
    # listing of open invoices for the sidebar in the dashboard by status
    path('app/ap/openinvoicessidebar/<company>', views.APUserManagerOpenInvoicesSidebarView.as_view(), name='ap-open-invoices-sidebar-by-status'),
    #listing of all paid invoices for the sidebar
    path('app/ap/paidinvoicessidebar/<company>', views.APUserManagerPaidInvoicesSidebarView.as_view(), name='ap-paid-invoices-side-bar'),
    #list all invoices a company has, is searchable and paginated.  Also has status and overdue url params that can be used.
    path('app/ap/invoicelistpage/<company>', views.APUserManagerInvoicesPageView.as_view(), name='ap-invoices-page'),
    #list all vendors that a company has
    path('app/ap/vendorlist/<company>', views.APVendorListPageView.as_view(), name='ap-vendor-list'),
    #list all vendors that a company has filtered by search term
    path('app/ap/vendorsearch/<company>', views.APVendorListPageView.as_view(), name='ap-vendor-basic-search'),
    #list company contact, bank acct, and credit card info
    path('app/ap/companysettings/<company>', views.APCompanySettingsListView.as_view(), name='ap-company-settings-list'),
    #add a bank account for a company
    path('app/ap/company/bankacct/add', views.APCreateBankAccountView.as_view(), name='company-settings-add-bankacct'),
    #set a default bank acct for a company
    path('app/ap/company/bankacct/setdefalt', views.APSetDefaultBankAccountView.as_view(), name='company-settings-set-default-bankacct'),
    #delete a bank account for a company
    path('app/ap/company/bankacct/delete', views.APDeleteBankAccountView.as_view(), name='company-settings-delete-bankacct'),
    #list potential approver invoices emails for vendor page and invoice page
    path('app/ap/company/approveremails/<company>', views.APApproverEmailsView.as_view(), name='approver-email-list'),
    #vendor listing page
    #path('app/ap/vendor/list/<company>/<vendor>', views.APVendorListView().as_view(),'vendor-list'),
    #add a bank account for a vendor from vendor page
    path('app/ap/vendor/bankacct/add', views.APCreateVendorBankAccountView.as_view(), name='vendor-add-bankacct'),
    # set a default bank acct for a vendor from vendor page
    path('app/ap/vendor/bankacct/setdefalt', views.APSetDefaultVendorBankAccountView.as_view(), name='vendor-set-default-bankacct'),
    #delete a bank account for a vendor from vendor page
    path('app/ap/vendor/bankacct/delete', views.APDeleteVendorBankAccountView.as_view(), name='vendor-delete-bankacct'),
    #list all bank accounts for a vendor from the vendor page
    path('app/ap/vendor/bankacct/list/<company>/<vendor>', views.APListVendorBankAccountView.as_view(), name='vendor-list-bankacct'),
    #create vendor payment preferences
    path('app/ap/vendor/preferences/payment/create', views.APCreateVendorPaymentPreferencesView.as_view(), name='vendor-add-payment-preference-method'),
    #update vendor payment preferences -- not being used
    path('app/ap/vendor/preferences/payment/update', views.APUpdateVendorPaymentPreferencesView.as_view(), name='vendor-update-payment-preference-method'),
    #list default vendor payment preferences
    path('app/ap/vendor/preferences/payment/<company>/<vendor>', views.APRetrieveVendorPaymentPreferencesView.as_view(), name='vendor-retrieve-payment-method'),
    #create vendor invoice preferences
    path('app/ap/vendor/preferences/invoice/create', views.APCreateVendorInvoivePreferencesView.as_view(), name='vendor-create-invoice-preference'),
    #update vendor invoice preferences
    path('app/ap/vendor/preferences/invoice/update', views.APUpdateVendorInvoivePreferencesView.as_view(), name='vendor-update-invoice-preference'),
    #list vendor invoice preferences
    path('app/ap/vendor/preferences/invoice/<company>/<vendor>', views.APListVendorInvoivePreferencesView.as_view(), name='vendor-list-invoice-preference'),
    #create/update default vendor approver(s) and tiers
    path('app/ap/vendor/defaultapprovers/save', views.APSaveVendorDefaultApproversView.as_view(), name='vendor-save-default-approvers'),
    #delete default vendor tiers
    path('app/ap/vendor/defaultapprovers/delete', views.APDeleteVendorDefaultApproversView.as_view(), name='vendor-delete-default-approvers'),
    #list default vendor approvers
    path('app/ap/vendor/defaultapprovers/<company>/<vendor>', views.APListVendorDefaultApproversView.as_view(), name='vendor-list-default-approvers'),
    #list recent vendor invoices(last 15)
    path('app/ap/vendor/invoices/unpaid/<company>/<vendor>', views.APListVendorRecentInvoicesView.as_view(), name='vendor-list-recent-invoices'),
    #list recent payments to a vendor(last 15)
    path('app/ap/vendor/payments/<company>/<vendor>', views.APListVendorRecentPaymentsView.as_view(), name='vendor-list-recent-invoices'),
    #create note for a vendor
    path('app/ap/vendor/note/create', views.APCreateVendorNoteView.as_view(), name='vendor-create-note'),
    #delete a note for a vendor
    path('app/ap/vendor/note/delete', views.APDeleteVendorNoteView.as_view(), name='vendor-delete-note'),
    #list all notes for a vendor
    path('app/ap/vendor/notes/<company>/<vendor>', views.APListVendorNotesView.as_view(), name='vendor-list-note'),
    #update company bank information
    path('app/company/update/bankinfo', views.UpdateCompanyBankInfoView.as_view(), name='update-bank-info'),


    ####utility functions to import account, class, and departments
    #utility function to save gl accounts for a company from quickbooks
    path('app/ap/utility/import/account', views.UtilityImportAccountView.as_view(), name='utility-import-account'),
    #utility function to add classes
    path('app/ap/utility/import/class', views.UtilityImportClassView.as_view(), name='utility-import-class'),
    # utility function to add departments
    path('app/ap/utility/import/department', views.UtilityImportDepartmentView.as_view(), name='utility-import-department'),
    # utility create a term for a company ---delete this
    path('app/utility/company/create/terms', views.UtilityCreateTermsView.as_view(), name='utility-create-term'),
    # utility onboarding a quickbooks vendor.
    path('app/utility/vendor/onboard', views.UtilityOnboardVendorView.as_view(), name='utility-quickbooks-onboard-vendor'),





    ###vendor onboard endpoints section
    #create onboard vendor token and save email
    path('onboard/vendor/create', views.CreateVendorOnboardEmailView.as_view(), name='create-vendor-onboard-email'),
    #list companies and their associated pending onboard vendors (i.e. vendor name, status, date_created, etc.)
    path('onboard/vendor/pending', views.ListCompanyVendorOnboardPendingView.as_view(), name='list-vendor-onboard-pending-list'),
    #list companies and their registered/accepted companies with old name and entered vendor data
    path('onboard/vendor/received', views.ListCompanyVendorOnboardReceivedView.as_view(), name='list-vendor-onboard-received-list'),
    #combined onboarding view for both pending and received
    path('onboard/vendor/all', views.ListCompanyVendorOnboardAllView.as_view(), name='list-vendor-onboard-all-list'),
    #resend(i.e. create a new) onboard vendor email for a given onboard vendor
    path('onboard/vendor/resend', views.ResendVendorOnboardEmailView.as_view(), name='resend-vendor-onboard-list'),
    #delete/invalidate a vendor onboard request
    path('onboard/vendor/delete', views.DeleteVendorOnBoardRequestView.as_view(), name='delete-vendor-onboard-request'),
    #hide received vendor onboard request
    path('onboard/vendor/received/hide', views.HideReceivedVendorOnboardRequestView.as_view(), name='hide-received-vendor-onboard-request'),
    #retrieve required vendor onboard/company information necessary for saving their data -- endpoint to hit for page when link in email is clicked
    path('onboard/vendor/retrieve/<token>', views.RetrieveVendorOnboardSetupView.as_view(), name='retrieve-vendor-onboard-setup-data'),
    #save all vendor onboard information -- switched to utility view
    #path('onboard/vendor/savedata', views.SaveVendorOnBoardView.as_view(), name='save-vendor-onboard-info'),
    #test route to create test scripts
    path('testview', views.ScriptTestView.as_view(), name='test-view'),


    # create an invoice either as a vendor or buyer
    path('company/invoice/receive', views.CreateInvoiceView.as_view(), name='create-invoice'),
    ##list all invoices a company has (type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar)
##    path('invoices/list/<type>', views.ListInvoicesView.as_view(), name='list-invoice'),
    ##list all invoices a company has for a business(type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar)
    ##companyid is the company id
##    path('company/invoices/list/<type>/<companyid>', views.ListInvoicesView.as_view(), name='list-invoice-company'),
    ##list all invoices a company has (type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar)
    ##overdue values are 0, 30, 60, 90, all
##    path('invoices/list/<type>/<overdue>', views.ListInvoicesView.as_view(), name='list-invoice'),
    ##list all invoices a company has for a business(type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar)
    ##companyid is the company id
    ##overdue values are 0, 30, 60, 90, all
##    path('company/invoices/list/<type>/<companyid>/<overdue>', views.ListInvoicesView.as_view(), name='list-invoice-company'),
    ##invoice/invoicelist detail
##    path ('invoice/display/<invoiceid>', views.DetailInvoiceView.as_view(), name='invoice-detail'),
    ##update invoices and invoicelines
##    path('invoice/update', views.UpdateInvoiceView.as_view(), name='invoice-update'),
    ##delete an invoice or invoiceline  accepts "id" as int or list, "type" is invoice to delete an invoice and its invoicelines or line to delete an invoice line
##    path('invoice/delete', views.DeleteInvoiceView.as_view(), name='delete-invoice'),
    ##send an info request email to zyllion
    #path('email/requestinfo', views.SendInfoEmail.as_view(), name='info-email')

]
