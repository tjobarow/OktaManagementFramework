# Introduction to OktaManagementFramework
I rarely need async calls for my scripts, so I wrote a synchronous wrapper for a lot of the common API calls I make against Okta. This wrapper is mainly used to fetch data versus make changes within Okta. It offers the following functionality:
## Users
### Getting users
You can use the class property ```users``` to have the class retrieve all users. Such as ```OktaManagementFramework.users```. 
### User lookup table
This also creates what I call a "user lookup table", which is essentially a dictionary of all the Okta users the class retrieved constructed as a dictionary, with the Okta user ID as the key, and the value the user's object returned from the API. This can be accessed through the class property ```user_lookup_table``` as in ```OktaManagementFramework.user_lookup_table```.
### Get user by id
If you only need specifc user objects and know their user id, you can call ```OktaManagementFramework.fetch_user_by_id(user_id)``` to return just that user object. __Note that if you make this function call after having already fetched all Okta users by invoking ```OktaManagementFramework.users```, invoking ```fetch_user_by_id(user_id)``` will pull from the user objects retrieved by the earlier invocation of ```.users```__.
## User Factors
### Getting factors for all users
Much like the property ```OktaManagementFramework.users```, you can invoke the class to retrieve all user factors by referencing the property ```OktaManagementFramework.user_factors```. __This takes a while to run as it has to retreive all okta users (if not already populated by ```OktaManagementFramework.users```) and then one by one get each user's factors. Sure, some concurrency would have been nice here, but damn rate limits__.
### Getting factors for a singular user
You can make a call to ```OktaManagementFramework.fetch_user_factors(user_id: str)``` to get the factors for a singular user, where user_id is the Okta user ID of the user you wish to return factors for.
### Unenroll a particular factor
You can unenroll a users factor by called ```OktaManagementFramework.unenroll_user_factor(user_id, factor_id)```.
### Enrolling a new push factor
You can use ```OktaManagementFramework.enroll_new_push_factor_v2(user_id)``` to enroll a new push factor for a particular user id. There is an old version of this function named ```enroll_new_push_factor(user_id)```, but either function should work. The v2 just has an updated way of activating the factor.
## Devices & their users (Registered devices)
### Get devices for all users
You can reference the class property ```users_with_devices``` (```OktaManagementFramework.users_with_devices```) to have a list returned containing all user identities, along with the devices registered to each, if any are.
### Get devices for specific user id
You can use the function call ```OktaManagementFramework.fetch_devices_for_user(user: dict)``` to get the devices for a specific user. Much like ```OktaManagementFramework.fetch_user_factors(user: dict)```, this function call only accepts the full user object instead of just a user id. I need to re-write the way this function works in the future.
### Old way of getting device users
The way you retrieve info on devices and users has evolved over time as Okta has improved their APIs functionality. You used to have to retrieve all devices from Okta, and then make an API for each device to retrieve the users for that device. There was no way at the time to make an API call to see which devices a specific user had registered to them without enumerating ALL DEVICES. Luckily, nowadays, there is an API call to do this. 
For this reason, I would avoid using the class property ```device_users``` or ```device_users_lookup_table``` as much as possible, unless you really need them. They should work, but are slow and are considered the "old" way of getting this information.
## Applications
### Get all applications
Reference the class property ```applications``` (```OktaManagementFramework.applications```) to get a list of all applications in the Okta tenant. 
### App lookup table
Much like my ```user_lookup_table```, the ```applications_lookup_table``` property is a dictionary where the key is the app id, and the value is the app info for that app id.
### Get app by id
You can call ```OktaManagementFramework.fetch_application_by_id(app_id)``` to return information regarding a specific application.
## Application Users
### Get application users
You can call ```OktaManagementFramework.fetch_application_users(app_id)``` to return a list of all users assigned to an application. **However, note tha the API only returns limited information about each user, not each users full profile.** To get a list of users assigned to an application, and have the full user profile returned for each user, do the following:
### Get application users with full profile
You can call ```OktaManagementFramework.fetch_application_users_with_full_profiles(app_id)``` to return a list of users assigned to an application, with all user information for each user (the full user object for each assigned user).
## Sign On / Access / Authentication Policies
### Get all sign on policies
Reference the class property ```OktaManagementFramework.sign_on_policies``` to return all the sign on/access/authentication policies present in the Okta tenant
### Sign on policy lookup table
Much like the other lookup tables, ```OktaManagementFramework.sign_on_policies_lookup_table``` class property is a dictionary where the key is the sign on policy id, and the value is the sign on policy object itself.
### Get sign on policy for application
Call the function ```OktaManagementFramework.fetch_app_sign_on_policy(app_details: dict)``` to return the assigned sign on policy for that specific application. The parameter app_details, much like some other function calls, is an app object returned from the Okta API. You can call ```OktaManagementFramework.get_app_by_id(app_id)``` and pass the returned value into this function. I need to re-write this to use app_id as a parameter, though.
### Update an apps sign on policy
You can call ```OktaManagementFramework.fetch_app_sign_on_policy(application_object: dcit, policy_object: dict)``` to update an app to use a new sign on policy, where ```application_object``` is an app object returned from ```OktaManagementFramework.get_app_by_id(app_id)``` and ```policy_object``` is a policy object returned from ```OktaManagementFramework.fetch_policy_by_id(policy_id)```. Need to update this to use just the app_id and policy_id.
### Get policy by id
Call the function ```OktaManagementFramework.fetch_policy_by_id(policy_id)``` to return the policy object for that particular policy id.
### Get sign on policy rules by policy id
Call the function ```OktaManagementFramework.get_rules_by_policy_id(policy_id)``` to return the rules associated with that particular sign on policy.

## System Log
### Get system log events
Make a call to ```OktaManagementFramework.get_okta_system_log_events(since: None | str = None,until: None | str = None, filter: None | str = None,query: None | str = None,next_page_url: None | str = None,)``` to return events from the system log. You can specific since (return events after a starting timestamp - iso8601), until (return events until an ending timestamp - iso8601), a filter string (like you would use to filter events in the Okta admin dashboard), or a query (not too sure the difference here, but I always use filter). 

# Building package from source
1. To build OktaManagementFramework from source, first clone the repo

```git clone git@github.com:tjobarow/OktaManagementFramework.git```

2. Create a new python virtual environment (if you have that module installed in python)

```python -m venv .my-venv```

3. Activate the environment (depends on OS)

- __Linux/MacOS:__

```source ./.my-venv/bin/activate```

- __Windows (PowerShell|CMD prompt)__

```./.my-venv/Scripts/[Activate.ps1|Activate.bat]```

4. Install buildtools & wheel

```pip install build wheel```

5. Build package from within cloned repo

```python -m build --wheel```

6. Install OktaManagementFramework using pip from within root directory of OktaManagementFramework
   
```pip install .``` 

# Quick start
## Import package
Import the package

```from okta_management_framework import OktaManagementFramework```

## Create new instance
Then, create a new instance of OktaManagementFramework, passing it the required parameters:

```okta = OktaManagementFramework(okta_domain="mycompany",api_token="TOKEN FROM OKTA")```

## Use it to pull information from Okta, such as users
```okta_users: list = okta.users```

## Optional: Provide a logger
If you want to explicitly provide a Python logging.Logger object for the class to use, provide it when you create the class:

```okta = OktaManagementFramework(okta_domain="mycompany",api_token="TOKEN FROM OKTA",logger=logging.getLogger("my-logger"))```

## Optional: Set IS_TESTING flag to true and provide TESTING_COUNT_THRESHOLD integer value to force class to return less Okta objects
If you are wanting to have OktaManagementFramework return less overall users, devices, etc. This can help you when you need to test and do not want to wait hours for it to return 10k user objects. Set IS_TESTING=True when you create the class:

```okta = OktaManagementFramework(okta_domain="mycompany",api_token="TOKEN FROM OKTA",IS_TESTING=True)```

Additionally, you can set the max number of objects to return by providing an integer value to TESTING_COUNT_THRESHOLD during class construction:

```okta = OktaManagementFramework(okta_domain="mycompany",api_token="TOKEN FROM OKTA",IS_TESTING=True,TESTING_COUNT_THRESHOLD=2000)```

## Optional: Set the ONLY_ACTIVE_USERS flag to true to only return active users
If you set the ONLY_ACTIVE_USERS flag to during during class construction, OktaManagementFramework.users will only return Okta user cccounts that are ACTIVE.

```okta = OktaManagementFramework(okta_domain="mycompany",api_token="TOKEN FROM OKTA", ONLY_ACTIVE_USERS=True)```
