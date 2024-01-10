# README #

### What is this repository for? ###

* This is the backend api for zyllion.co.  This is written using django-rest framework and provides all of the 
endpoints consumed/used by the frontend react application  
* version 1.0.0

### How do I get set up? ###

* Install python version 3.6.5 or 3.6.7 if on windows
* Install pip
* Install virtual environment and create a virtual environment
* Either connect to the external db 
*  - OR - 
* Install postgres v 10.
* Create a postgres user
* Import database
* Grant the user privileges
* Assign the User to a group
* Clone the repo
* Install all requirements from requirements.txt
* Change postgres username/password in the settings.py file
* Open the terminal/shell as an adimn and cd to the project location
* Start the virtual environment
* From the console run python manage.py makemigrations data
* From the console run python manage.py migrate

### Endpoints List ###
##### Create initial account including the account, account contact information and initial user #####
* ```'api/account/create'```
##### logout a user/invalidate all of their jwts #####
* ```'api/user/logout/all'```
##### Log in a user #####
* ```'api/user/login/'```
##### Refresh jwt token ##### 
* ```'api/user/login/refresh'```
##### Retrieve Account, ContactInfo data for account update #####
* ```'api/account/detaildata'```
##### Update Account/ContactInfo data #####
* ```'api/account/update'```
##### Check for valid email addresses #####
* ```'api/user/emailcheck/<email>'```
##### Add new Company #####
* ```'api/company/create'```
##### Add new Business #####
* ```'api/business/create'```
##### Update a  Company #####
* ```'api/company/update'```
##### Create a self contained business a company works with #####
* ```'api/business/create'```
##### List systems based off of plan signed up for #####
* ```'api/account/systems'```
#####Ceate a new user for the company #####
* ```'api/user/create'```
##### Update an existing users information or own user information #####
* ```'api/user/update'```
##### Deactivate/activate a user (uid: id of user to be deactivated/activated, is_active: 1 to activate, 0 to deactivate)#####
* ```'api/user/status'```
##### Update password #####
* ```'api/user/password/update'```
##### List all signup plans information #####
* ```'api/plan/list'```
##### List the logged in users information#####
* ```api/user/list```
##### List all users for a company based on role #####
* ```'api/user/list/<companyid>'```
##### List individual user information for updating own user information #####
* ```'api/user/display'```
##### List individual user information for updating user information via admin interface #####
* ```'api/user/display/<userid>'```
##### list all available groups a user can be added to when creating or updating based off on logged in user permission #####
* ```'api/user/availablegroups'```
##### list all available companies a user can be added to when creating or updating based off of logged in user#####
* ```'api/user/availablecompanies'```
##### Create an invoice either as a vendor or buyer #####
* ```'api/company/invoice/create'```
##### List all invoices a company has (type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar) #####
* ```'api/invoices/list/<type>'```
##### List all invoices a company has for a business(type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar), companyid is the company id #####
* ```'api/company/invoices/list/<type>/<companyid>'```
##### List all invoices a company has (type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar), overdue values are 0, 30, 60, 90, all #####
* ```'api/invoices/list/<type>/<overdue>'```
##### List all invoices a company has for a business(type:1 denotes selecting for buyer(i.e. ap), type:2 denotes selecting for vendor(i.e. ar), companyid is the company id, overdue values are 0, 30, 60, 90, all #####
* ```'api/company/invoices/list/<type>/<companyid>/<overdue>'```
##### Invoice/invoicelist detail #####
* ```'api/invoice/display/<invoiceid>'```
##### Update invoices and invoicelines #####
* ```'api/invoice/update'```
##### Delete an invoice or invoiceline  accepts "id" as int or list, "type" is invoice to delete an invoice and its invoicelines or line to delete an invoice line #####
* ```'api/invoice/delete'```

### Link to download Postman Collection of endpoints ###

* Link contains the endpoints and examples of expected payloads/variables for the endpoints

* Either import using the link or copy and paste the contents when importing the collection to postman

* ``` https://www.getpostman.com/collections/ead074788554f14764bf```


