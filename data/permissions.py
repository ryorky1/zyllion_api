from rest_framework import permissions



class IsAcctManager(permissions.BasePermission):
    message = "Insufficient permission to access page"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name='Account manager'):
            return True
        return False

class IsAdmin(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name='Admin'):
            return True
        return False

class IsManager(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AP manager', 'AR manager']):
            return True
        return False

class IsUser(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AP manager', 'AR manager', 'AP user', 'AP user', 'Onboard user']):
            return True
        return False

class IsAPManager(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AP manager']):
            return True
        return False

class IsAPUser(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AP manager', 'AP user', 'Onboard user']):
            return True
        return False

class IsARManager(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AR manager']):
            return True
        return False

class IsARUser(permissions.BasePermission):
    message = "You do not have access to this information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AR manager', 'AR user']):
            return True
        return False

class IsOnboardUser(permissions.BasePermission):
    message = "You do not have access to this Information"
    def has_permission(self, request, view):
        if request.user and request.user.groups.filter(name__in=['Admin', 'AP manager', 'Onboard user']):
            return True
        return False