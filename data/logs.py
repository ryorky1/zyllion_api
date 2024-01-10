from .serializers import AccountPlanLogSerializer, UserLogSerializer, InvoiceLogSerializer

def accountlogger(acct, self):
    acctPlanLog = AccountPlanLogSerializer(data=self.request.data)
    if acctPlanLog.is_valid():
        acctPlanLog.save(account=acct, user=self.request.user.id)

def userlogger(self, user, action):
    log_data = {"modifier":self.request.user.id, "account":user.account.id, "user":user.id, "action":action}
    userLogEntry = UserLogSerializer(data=log_data)
    if userLogEntry.is_valid(raise_exception=True):
        userLogEntry.save()

def invoicelogger(self, invoice, action):
    user = self.request.user.id if self.request.user.id else None
    account = self.request.user.account.id if self.request.user.account.id else None


    invoicelog_data = {"account":account, "companylink":invoice.companylink.id, "modifier":user, "invoice":invoice.id,
                       "status":invoice.status.id, "action":action}
    invoiceLogEntry = InvoiceLogSerializer(data=invoicelog_data)
    if invoiceLogEntry.is_valid(raise_exception=True):
        invoiceLogEntry.save()
