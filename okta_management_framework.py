#!/.venv-linux/bin/ python
# -*-coding:utf-8 -*-
"""
@File    :   OktaManagementFramework.py
@Time    :   2024/06/06 15:37:48
@Author  :   Thomas Obarowski 
@Version :   .10
@Contact :   tjobarow@gmail.com
@License :   MIT License
@Desc    :   None
"""

# Import built-in modules
import re
import sys
import time
import json
import logging
import urllib.parse
from functools import wraps
from datetime import datetime, timezone

# Import pip installed packages
import requests


class OktaRateLimitExceededError(Exception):
    def __init__(
        self, headers: dict, message="Okta API rate limit exceeded. Retrying...",
    ):
        self.message = message
        self.headers = headers
        super().__init__(self.message)


class OktaManagementFramework:

    def __init__(
        self,
        okta_domain: str,
        api_token: str,
        logger: logging.Logger = None,
        IS_TESTING: bool = False,
        TESTING_COUNT_THRESHOLD: int = 100,
        ONLY_ACTIVE_USERS: bool = False,
    ):
        ####
        #### PRIVATE/PROTECTED CLASS FIELDS
        # CONFIGURATION RELATED PROTECTED/PRIVATE CLASS FIELDS
        self._okta_domain: str = None
        self.__api_token: str = None
        self._OKTA_RATE_AVOID_TIMER: float = 0.5
        self._logger: logging.Logger = None
        self._ONLY_ACTIVE_USERS = ONLY_ACTIVE_USERS

        # If this flag is set, then certain loops will purposefully terminate
        # prematurely, as to shorten testing time. Some data, under normal
        # conditions, could take hours to fetch, due to the shear number of resources
        # that exist in Okta for that resource type (such as getting all users for
        # every SINGLE device in Okta).
        self.__IS_TESTING: bool = IS_TESTING
        self.__TESTING_COUNT_THRESHOLD: int = (TESTING_COUNT_THRESHOLD - 400)

        # DEVICE RELATED PROTECTED/PRIVATE CLASS FIELDS
        self.__devices: list[dict] = None
        self.__devices_lookup_table: dict[dict] = None
        self.__device_users: list[dict] = None
        self.__device_users_lookup_table: dict[dict] = None
        self.__users_with_devices: list["dict"] = None

        # USER RELATED PROTECTED/PRIVATE CLASS FIELDS
        self.__users: list[dict] = None
        self._users_lookup_table: dict[dict] = None
        self.__user_devices_lookup_table: dict[dict] = None
        self.__retrieved_user_profile_cache: dict[dict] = {}

        # USER FACTOR RELATED CLASS FIELDS
        self.__user_factors: list[dict] = None

        # APPLICATION RELATED PROTECTED/PRIVATE CLASS FIELDS
        self.__applications: list[dict] = None
        self.__applications_lookup_table: dict[dict] = None

        # POLICY RELATED PROTECTED/PRIVATE CLASS FIELDS
        self.__sign_on_policies: list[dict] = None
        self.__sign_on_policies_lookup_table: dict[dict] = None

        ####
        #### PUBLIC CLASS FIELDS
        # CONFIG RELATED PUBLIC CLASS FIELDS
        if logger == None:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger
        self.okta_domain: str = okta_domain
        self.api_token: str = api_token

        # DEVICE RELATED PUBLIC CLASS FIELDS
        self.devices: list[dict] = None
        self.devices_lookup_table: dict[dict] = None
        self.device_users: list[dict] = None
        self.users_with_devices: list[dict] = None

        # USER RELATED PUBLIC CLASS FIELDS
        self.users: list[dict] = None
        self.users_lookup_table: dict[dict] = None

        # USER FACTORS RELATED CLASS FIELDS
        self.user_factors: list[dict] = None

        # APPLICATION RELATED PUBLIC CLASS FIELDS
        self.applications: list[dict] = None

        # SIGN ON POLICIES RELATED PUBLIC CLASS FIELDS
        self.sign_on_policies: list[dict] = None

        self._logger.info(
            "Finished initializing OktaManagementFramework class instance."
        )

    def validate_attrs_present(func):
        """This function is used as a decorator, and will validate that the
        current value of this classes  self.__api_token and self._okta_domain
        are not None before executing the function it's called with

        Args:
            func (_type_): Function to execute if the class attribute values
            are not None

        Raises:
            ValueError: Raised if self.__api_tokens is None
            ValueError: raised if self._okta_domain is None
            value_error: We catch the original value error from above, log it,
            and raise the original error to the calling function

        Returns:
            _type_: Results of the function passed as a parameter
        """

        @wraps(func)
        def validate_api_token_exists(self, *args, **kwargs):
            try:
                if self.__api_token is None:
                    raise ValueError(
                        "The current Okta API token is null. Cannot proceed."
                    )
                elif self._okta_domain is None:
                    raise ValueError("The current Okta domain is null. Cannot proceed.")
            except ValueError as value_error:
                self._logger.error(value_error)
                raise value_error

            return func(self, *args, **kwargs)

        return validate_api_token_exists

    """
    #work in progress
    def okta_rate_limit_backoff(retries=3):
        def decorator(func):
            def wrapper(self, *args, **kwargs):
                try:
                    return func(self, *args, **kwargs)
                except OktaRateLimitExceededError as e:
                    rate_limit_reset_ts_int: int = int(e.headers["x-rate-limit-reset"])
                    time_to_wait: int = rate_limit_reset_ts_int - int(time.time())
                    self._logger.debug(f"Current time is {datetime.fromtimestamp(time.time(),tz=timezone.utc).strftime('%H:%M:%S %Y-%m-%d')} but rate limit does not reset until {datetime.fromtimestamp(rate_limit_reset_ts_int,tz=timezone.utc).strftime('%H:%M:%S %Y-%m-%d')}. Waiting until rate limit resets to continue")
                    self._logger.warning(f"Waiting {time_to_wait} seconds until rate limit resets.")
                    time.sleep(time_to_wait)
                    return func(self, *args, **kwargs)
                
                    current_retry = 0
                    self._logger.debug(
                        "Headers supplied to raised OktaRateLimitExceededError - will base backoff on returned x-rate-limit-reset value."
                    )
                    while time.time() < int(e.headers["x-rate-limit-reset"]):
                        if current_retry > retries:
                            self._logger.error(f"Maximum retries of {retries} was exceeded - raising OktaRateLimitExceededError and ending backoff")
                            raise e
                        self._logger.warning(
                            f"Current time is {datetime.fromtimestamp(time.time(),tz=timezone.utc).strftime('%H:%M:%S %Y-%m-%d')} but rate limit does not reset until {datetime.fromtimestamp(int(e.headers['x-rate-limit-reset']),tz=timezone.utc).strftime('%H:%M:%S %Y-%m-%d')}"
                        )
                        wait_period: int = (
                            int(e.headers["x-rate-limit-reset"]) - time.time()
                        )
                        self._logger.warning(
                            f"Waiting {wait_period} seconds for rate limit reset."
                        )
                        time.sleep(wait_period)
                        current_retry += 1
            return wrapper
        return decorator"""

    def rate_limit_backoff(delay=2, retries=3):
        def decorator(func):
            def wrapper(self, *args, **kwargs):
                current_retry = 0
                current_delay = delay
                while current_retry < retries:
                    try:
                        return func(self, *args, **kwargs)
                    except Exception as e:
                        current_retry += 1
                        if current_retry >= retries:
                            raise e
                        self._logger.warning(
                            f"Retrying in {current_delay} seconds..."
                        )
                        time.sleep(current_delay)
                        current_delay *= 2

            return wrapper

        return decorator

    ###########################################################################
    # SECTION OF CODE RELATING TO CLASS UNDERLYING CONFIGURATION
    ###########################################################################

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @logger.setter
    def logger(self, value: logging.Logger) -> None:
        """Sets the logger object for the class

        Args:
            value (logging.Logger): A logger object for the class
        """
        self._logger = value

    @property
    def okta_domain(self) -> str:
        """Returns value of Okta domain

        Returns:
            str: value of Okta domain
        """
        return self._okta_domain

    @okta_domain.setter
    def okta_domain(self, value: str) -> None:
        """Sets the value of self.okta_domain

        Args:
            value (str): value of Okta domain

        Raises:
            ValueError: Raised if the value is None or a blank string
            TypeError: Raised if the value is not a str
            value_error: Raised to the calling function after logging the error
            type_error: Raised to the calling function after logging the error
        """
        try:
            if value is None or value == "":
                raise ValueError("okta_domain cannot be None or an empty string.")
            elif not isinstance(value, str):
                raise TypeError(
                    f"okta_domain must be of type str, but was {type(value)}."
                )
            else:
                self._okta_domain = value
        except ValueError as value_error:
            self._logger.critical(value_error)
            raise value_error
        except TypeError as type_error:
            self._logger.critical(type_error)
            raise type_error

    @property
    def api_token(self) -> bool:
        """Returns True or False based on if the API token is defined. We want to
        protect the value of the api_token so we do not want a normal getter method
        that returns the value of the token.

        Returns:
            bool: Returns True or False based on if the API token is defined or None
        """

        return True if self.__api_token is not None else False

    @api_token.setter
    def api_token(self, value: str) -> None:
        """Sets the value of self.__api_token

        Args:
            value (str): value of Okta api token

        Raises:
            ValueError: Raised if the value is None or a blank string
            TypeError: Raised if the value is not a str
            value_error: Raised to the calling function after logging the error
            type_error: Raised to the calling function after logging the error
        """
        try:
            if value is None or value == "":
                raise ValueError("api_token cannot be None or an empty string.")
            elif not isinstance(value, str):
                raise TypeError(
                    f"api_token must be of type str, but was {type(value)}."
                )
            else:
                self.__api_token = value
        except ValueError as value_error:
            self._logger.critical(value_error)
            raise value_error
        except TypeError as type_error:
            self._logger.critical(type_error)
            raise type_error

    ###########################################################################
    # SECTION OF CODE TO FETCH DEVICES
    ###########################################################################
    @property
    def devices(self) -> list:
        if self.__devices == None:
            self._logger.debug("Loading Okta devices")
            self.__devices = self.__fetch_devices()
        self._logger.debug(f"Returning {len(self.__devices)} devices from Okta.")
        return self.__devices

    @devices.setter
    def devices(self, value: list) -> None:
        self._logger.debug("Okta Devices setter called. Will fetch Okta devices")
        self.__devices: list = value

    @property
    def devices_lookup_table(self) -> list:
        if self.__devices_lookup_table == None:
            self._logger.debug(
                "The device_lookup_table is empty. Will populate the table."
            )
            if self.devices == None:
                self._logger.debug("Loading Okta devices to create lookup table")
                self.devices = self.__fetch_devices()

            self.devices_lookup_table = self.devices
        self._logger.debug(
            f"Returning {len(self.__devices_lookup_table)} devices from Okta."
        )
        return self.__devices_lookup_table

    @devices_lookup_table.setter
    def devices_lookup_table(self, value: list) -> None:
        self._logger.debug(
            "Setter for devices_lookup_table was called. Creating dictionary where key == device['id'], value = device: dict"
        )
        if value == None:
            self._logger.debug(
                "Value provided to users_lookup_table setter was None, so returning without making table."
            )
            return
        devices_lookup_table: dict[dict] = {}
        for device in value:
            if device["id"] not in devices_lookup_table:
                devices_lookup_table.update({device["id"]: device})

        self.__devices_lookup_table = devices_lookup_table

        self._logger.debug(
            f"Created devices_lookup_table with length {len(self.__devices_lookup_table)}"
        )

    @validate_attrs_present
    def __fetch_devices(
        self, next_page_url: str = None, TRACK_COUNT_FOR_TESTING: int = 0
    ) -> list:

        if not next_page_url:
            self._logger.info("Fetching Okta devices...")

        device_list = []

        url = f"https://{self._okta_domain}.okta.com/api/v1/devices"

        if next_page_url:
            self._logger.info("Fetching next page of Okta devices...")
            full_url = next_page_url
        else:
            full_url = url + "?limit=1000"

        payload = {}
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
            "User-Agent": "okta-management-framework/1.0.0",
        }

        try:
            self._logger.debug(
                f"Sleeping for {self._OKTA_RATE_AVOID_TIMER} seconds to avoid Okta API rate limits."
            )
            time.sleep(self._OKTA_RATE_AVOID_TIMER)
            response = requests.request("GET", full_url, headers=headers, data=payload)
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    "Okta response states there as an error."
                )

            device_list += data

        except requests.exceptions.RequestException as req_error:
            self._logger.error(str(req_error))
            self._logger.error("Error occurred fetching devices, terminating script.")
            sys.exit(1)
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error("Error occurred fetching devices, terminating script.")
            sys.exit(1)

        try:
            if ' rel="next"' in dict(response.headers)["link"]:
                pattern = r'<.*?;\srel="self",\s<(.*?)>;\srel="next"$'
                match = re.search(pattern, dict(response.headers)["link"])

                if match:
                    if self.__IS_TESTING and (
                        TRACK_COUNT_FOR_TESTING >= self.__TESTING_COUNT_THRESHOLD
                    ):
                        self._logger.warning(
                            f"IS_TESTING flag was set during __fetch_devices. {self.__TESTING_COUNT_THRESHOLD} or more devices have been fetched, so recursion will end early."
                        )
                        return device_list

                    next_page_url = match.group(1)
                    self._logger.debug(f"URL for next page of data: {next_page_url}")
                    device_list += self.__fetch_devices(
                        next_page_url=next_page_url,
                        TRACK_COUNT_FOR_TESTING=TRACK_COUNT_FOR_TESTING
                        + len(device_list),
                    )
                else:
                    self._logger.debug("No match found for next URL.")
        except KeyError:
            self._logger.error("Link not found in reponse headers, must be all devices")

        return device_list

    ###########################################################################
    # SECTION OF CODE TO FETCH USERS
    ###########################################################################

    @property
    def users(self) -> list:
        if self.__users == None:
            self._logger.debug("Loading Okta users")
            self.users = self.__fetch_users()
        self._logger.debug(f"Returning {len(self.__users)} users from Okta.")
        return self.__users

    @users.setter
    def users(self, value: list) -> None:
        self._logger.debug("Okta users setter called. Will fetch Okta users")
        self.__users: list = value
        self._users_lookup_table: dict[dict] = value
        if value is not None:
            for user in value:
                self.__add_user_to_cache(user_profile=user)

    @property
    def users_lookup_table(self) -> list:
        if self._users_lookup_table == None:
            self._logger.debug(
                "The user_lookup_table is empty. Will populate the table."
            )
            if self.users == None:
                self._logger.debug("Loading Okta users to create lookup table")
                self.users = self.__fetch_users()

            self.users_lookup_table = self.users
        self._logger.debug(
            f"Returning {len(self._users_lookup_table)} users from Okta."
        )
        return self._users_lookup_table

    @users_lookup_table.setter
    def users_lookup_table(self, value: list) -> None:
        self._logger.debug(
            "Setter for users_lookup_table was called. Creating dictionary where key == user['id'], value = user: dict"
        )
        if value == None:
            self._logger.debug(
                "Value provided to users_lookup_table setter was None, so returning without making table."
            )
            return
        users_lookup_table: dict[dict] = {}
        for user in value:
            if user["id"] not in users_lookup_table:
                users_lookup_table.update({user["id"]: user})
        self._users_lookup_table = users_lookup_table
        self._logger.debug(
            f"Created users_lookup_table with length {len(users_lookup_table)}"
        )

    @validate_attrs_present
    @rate_limit_backoff(delay=1, retries=5)
    def __fetch_users(
        self, next_page_url: str = None, TRACK_COUNT_FOR_TESTING: int = 0
    ) -> list:

        if not next_page_url:
            self._logger.info("Fetching Okta users...")

        user_list = []

        url = f"https://{self._okta_domain}.okta.com/api/v1/users"

        if next_page_url:
            self._logger.info("Fetching next page of Okta users...")
            full_url = next_page_url
        else:
            url_query_params = "limit=200"
            if self._ONLY_ACTIVE_USERS:
                self._logger.debug("Flag set to only return active users")
                url_query_params += "&filter=status eq 'ACTIVE'"
            full_url = url + "?" + urllib.parse.quote_plus(url_query_params)

        payload = {}
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
            "User-Agent": "okta-management-framework/1.0.0",
        }

        try:
            """self._logger.debug(
                f"Sleeping for {self._OKTA_RATE_AVOID_TIMER} seconds to avoid Okta API rate limits."
            )
            time.sleep(self._OKTA_RATE_AVOID_TIMER)"""
            response = requests.request("GET", full_url, headers=headers, data=payload)
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    "Okta response states there as an error."
                )

            user_list += data

        except requests.exceptions.RequestException as req_error:
            self._logger.error(str(req_error))
            self._logger.error("Error occurred fetching users, terminating script.")
            sys.exit(1)
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error("Error occurred fetching users, terminating script.")
            sys.exit(1)

        try:
            if ' rel="next"' in dict(response.headers)["link"]:
                pattern = r'<.*?;\srel="self",\s<(.*?)>;\srel="next"$'
                match = re.search(pattern, dict(response.headers)["link"])

                if match:

                    if self.__IS_TESTING and (
                        (TRACK_COUNT_FOR_TESTING - 200)
                        >= self.__TESTING_COUNT_THRESHOLD
                    ):
                        self._logger.warning(
                            f"IS_TESTING flag was set during __fetch_users. {self.__TESTING_COUNT_THRESHOLD} or more users have been fetched, so recursion will end early."
                        )
                        return user_list

                    next_page_url = match.group(1)
                    self._logger.debug(f"URL for next page of data: {next_page_url}")
                    user_list += self.__fetch_users(
                        next_page_url=next_page_url,
                        TRACK_COUNT_FOR_TESTING=TRACK_COUNT_FOR_TESTING
                        + len(user_list),
                    )
                else:
                    self._logger.debug("No match found for next URL.")

        except KeyError:
            self._logger.error("Link not found in reponse headers, must be all users")

        return user_list

    @validate_attrs_present
    def fetch_user_by_id(self, user_id: str) -> dict:
        self._logger.debug(f"Will fetch full user profile details for {user_id}")
        full_url = f"https://{self._okta_domain}.okta.com/api/v1/users/{user_id}"

        # check the cache to see if the user has been retrieved within this class instance
        __cached_user: dict | None = self.__check_cache_for_user(user_id=user_id)
        if isinstance(__cached_user, dict):
            self._logger.debug(
                f"The user id {user_id} was found in this class instances user cache. Returning cached copy of user profile."
            )
            return __cached_user

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        payload = {}
        try:
            response = requests.request(
                method="GET", url=full_url, headers=headers, data=payload
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    f"Okta response states there is an error when fetching user profile for user id {user_id}."
                )
            # TODO FINISH IMPLEMENTING USER CACHE
            self.__add_user_to_cache(data)

            return data

        except requests.exceptions.RequestException as req_error:
            self._logger.error(str(req_error))
            self._logger.error(
                f"An error occurred while fetching user details for user {user_id}"
            )
            raise req_error
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error(
                f"An unanticipated exception was raised when fetching user details for user {user_id}. Unable to fetch user details"
            )
            raise error

    def __add_user_to_cache(self, user_profile: dict) -> None:
        self._logger.debug(f"Adding user {user_profile['id']} to local user cache")
        if user_profile["id"] not in self.__retrieved_user_profile_cache:
            self.__retrieved_user_profile_cache.update(
                {user_profile["id"]: user_profile}
            )

    def __check_cache_for_user(self, user_id: str) -> dict | None:
        return (
            self.__retrieved_user_profile_cache[user_id]
            if user_id in self.__retrieved_user_profile_cache
            else None
        )

    ###########################################################################
    # SECTION OF CODE TO FETCH USER FACTORS
    # TODO CREATE USER FACTOR LOOKUP TABLE?
    ###########################################################################
    @property
    def user_factors(self) -> list:
        if self.__user_factors == None:
            self._logger.debug("Loading Okta user factors")
            self.__user_factors = self.__fetch_factors_for_all_users()
        self._logger.debug(
            f"Returning {len(self.__users)} users with their factors from Okta."
        )
        return self.__user_factors

    @user_factors.setter
    def user_factors(self, value: list) -> None:
        self._logger.debug(
            "Okta user factors setter called. Will fetch Okta user factors"
        )
        self.__user_factors: list = value

    def __fetch_factors_for_all_users(self) -> list:
        self._logger.debug("Fetching enrolled factors for each user...")

        self._logger.debug(
            "Calling self.users function to retrieve list of Okta users into local scope. This will fetch from API if users are not already defined within this class instance."
        )
        users: list = self.users
        self._logger.debug(f"Calling self.users returned {len(users)}")

        self._logger.debug(
            "Will enumerate all users in list and fetch their currently enrolled factors."
        )
        user_factors: list[dict] = []
        for user in users:
            if (
                self.__IS_TESTING
                and ((users.index(user)) + 1) >= self.__TESTING_COUNT_THRESHOLD
            ):
                self._logger.warning(
                    f"The IS_TESTING flag was set to true, and {self.__TESTING_COUNT_THRESHOLD} user factors have been fetched, will now break out of loop"
                )
                break
            try:
                self._logger.debug(
                    f"#{(users.index(user))+1}/{len(users)}: Fetching enrolled factors for {user['id']}"
                )
                user_factors.append(
                    {"user": user, "factors": self.fetch_user_factors(user_id=user['id'])}
                )
            except requests.exceptions.RequestException as req_error:
                self._logger.error(req_error)
            except Exception as error:
                self._logger.error(error)

        return user_factors

    @validate_attrs_present
    @rate_limit_backoff(delay=1, retries=5)
    def fetch_user_factors(self, user_id: str) -> list[dict]:
        self._logger.debug(f"Fetching enrolled factors for user {user_id}")

        full_url = (
            f"https://{self._okta_domain}.okta.com/api/v1/users/{user_id}/factors"
        )

        payload = {}
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
            "User-Agent": "okta-management-framework/1.0.0",
        }

        try:
            """self._logger.debug(
                f"Sleeping for {self._OKTA_RATE_AVOID_TIMER} seconds to avoid Okta API rate limits."
            )
            time.sleep(self._OKTA_RATE_AVOID_TIMER)"""

            response = requests.request("GET", full_url, headers=headers, data=payload)
            response.raise_for_status()
            if "error" in response.json():
                raise requests.exceptions.RequestException(
                    "Okta response states there as an error."
                )
            elif len(response.json()) == 0:
                self._logger.warning(
                    f"User {user_id} does not have any enrolled factors."
                )
            elif len(response.json()) > 0:
                self._logger.debug(
                    f"Successfully fetched {len(response.json())} factors for user {user_id}"
                )
            return response.json()

        except requests.exceptions.RequestException as req_error:
            self._logger.error(
                f"Error occurred fetching user factors for user {user_id}"
            )
            raise req_error
        except Exception as error:
            self._logger.error(
                f"Error occurred fetching user factors for user {user_id}"
            )
            raise error

        ###########################################################################

    def unenroll_user_factor(self, user_id: str, factor_id: str) -> bool:
        user_id = user_id
        try:
            self._logger.info(
                f"Will attempt to unenroll factor {factor_id} for user {user_id}"
            )
        except KeyError:
            self._logger.info(
                f"Will attempt to unenroll factor {factor_id} for user {user_id}"
            )

        base_url = f"https://{self._okta_domain}.okta.com"
        api_path_params = f"/api/v1/users/{user_id}/factors/{factor_id}"
        full_url = base_url + api_path_params

        payload = {}
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        try:
            response = requests.delete(url=full_url, headers=headers, data=payload)
            response.raise_for_status()
            try:
                self._logger.info(
                    f"Successfully unenrolled factor {factor_id} for user {user_id}"
                )
            except KeyError:
                self._logger.info(
                    f"Successfully unenrolled factor {factor_id} for user {user_id}"
                )
            return True
        except requests.HTTPError as http_err:
            try:
                self._logger.error(
                    f"HTTP error occurred while unenrolling factor {factor_id} for {user_id}."
                )
            except KeyError:
                self._logger.error(
                    f"HTTP error occurred while unenrolling factor {factor_id} for {user_id}."
                )
            finally:
                self._logger.error(f"{http_err}")
                return False
        except requests.Timeout as timeout_err:
            try:
                self._logger.error(
                    f"Timeout error occurred while unenrolling factor {factor_id} for {user_id}."
                )
            except KeyError:
                self._logger.error(
                    f"Timeout error occurred while unenrolling factor {factor_id} for {user_id}."
                )
            finally:
                self._logger.error(f"{timeout_err}")
                return False
        except requests.RequestException as err:
            try:
                self._logger.error(
                    f"Generic error occurred while unenrolling factor {factor_id} for {user_id}."
                )
            except KeyError:
                self._logger.error(
                    f"Generic error occurred while unenrolling factor {factor_id} for {user_id}."
                )
            finally:
                self._logger.error(f"{err}")
                return False

    def enroll_new_push_factor(self, user_id: str) -> dict:
        self._logger.info(
            f"Enrolling new push factor for {user_id}. This will generate a enroll QR code."
        )

        base_url = f"https://{self._okta_domain}.okta.com"
        api_path_params = (
            f"/api/v1/users/{user_id}/factors?tokenLifetimeSeconds=86400&activate=true"
        )
        full_url = base_url + api_path_params

        payload = {"factorType": "push", "provider": "OKTA"}

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }

        try:
            response = requests.post(url=full_url, headers=headers, json=payload)
            response.raise_for_status()
            self._logger.info(
                f"Successfully enrolled a new push factor for user {user_id}"
            )
            self._logger.debug(json.dumps(response.json(), indent=4))
            return response.json()
        except requests.HTTPError as http_err:
            try:
                self._logger.error(
                    f"HTTP error occurred while enrolling new factor for {user_id}."
                )
            except KeyError:
                self._logger.error(
                    f"HTTP error occurred while enrolling new factor for {user_id}."
                )
            finally:
                self._logger.error(f"{http_err}")
                return False
        except requests.Timeout as timeout_err:
            self._logger.error(
                f"Timeout error occurred while enrolling new factor for {user_id}."
            )
            self._logger.error(f"{timeout_err}")
            return False
        except requests.RequestException as err:
            self._logger.error(
                f"Generic error occurred while enrolling new factor for {user_id}."
            )
            self._logger.error(f"{err}")
            return False
        except Exception as err:
            self._logger.error(
                f"An unexpected error occurred while enrolling new factor for {user_id}."
            )
            self._logger.error(f"{err}")
            return False

    def enroll_new_push_factor_v2(self, user_id: str) -> dict:
        self._logger.info(
            f"Enrolling new push factor for {user_id}. This will generate a enroll QR code."
        )

        base_url = f"https://{self._okta_domain}.okta.com"
        api_path_params = f"/api/v1/users/{user_id}/factors?tokenLifetimeSeconds=86400"
        full_url = base_url + api_path_params

        payload = {"factorType": "push", "provider": "OKTA"}

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }

        try:
            response = requests.post(url=full_url, headers=headers, json=payload)
            response.raise_for_status()
            self._logger.info(
                f"Successfully enrolled a new push factor for user {user_id}"
            )
            self._logger.debug(json.dumps(response.json(), indent=4))
            enrollment_resp: dict = response.json()
            factor_id: str = enrollment_resp["id"]
            activation_resp: dict = self.__activate_new_push_factor(user_id, factor_id)
            return {"enrollment": enrollment_resp, "activation": activation_resp}
        except requests.HTTPError as http_err:
            try:
                self._logger.error(
                    f"HTTP error occurred while enrolling new factor for {user_id}."
                )
            except KeyError:
                self._logger.error(
                    f"HTTP error occurred while enrolling new factor for {user_id}."
                )
            finally:
                self._logger.error(f"{http_err}")
                return False
        except requests.Timeout as timeout_err:
            self._logger.error(
                f"Timeout error occurred while enrolling new factor for {user_id}."
            )
            self._logger.error(f"{timeout_err}")
            return False
        except requests.RequestException as err:
            self._logger.error(
                f"Generic error occurred while enrolling new factor for {user_id}."
            )
            self._logger.error(f"{err}")
            return False
        except Exception as err:
            self._logger.error(
                f"An unexpected error occurred while enrolling new factor for {user_id}."
            )
            self._logger.error(f"{err}")
            return False

    def __activate_new_push_factor(self, user_id: str, factor_id: str) -> dict:
        self._logger.info(f"Activating new push factor {factor_id} for {user_id}.")

        base_url = f"https://{self._okta_domain}.okta.com"
        api_path_params = (
            f"/api/v1/users/{user_id}/factors/{factor_id}/lifecycle/activate"
        )
        full_url = base_url + api_path_params

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }

        try:
            response = requests.post(url=full_url, headers=headers, json={})
            response.raise_for_status()
            self._logger.info(
                f"Successfully activated a new push factor {factor_id} for user {user_id}"
            )
            self._logger.debug(json.dumps(response.json(), indent=4))
            return response.json()
        except requests.HTTPError as http_err:

            self._logger.error(
                f"HTTP error occurred while activating new factor {factor_id} for {user_id}."
            )
            self._logger.error(f"{http_err}")
            return False
        except requests.Timeout as timeout_err:
            self._logger.error(
                f"Timeout error occurred while activating new factor {factor_id} for {user_id}."
            )
            self._logger.error(f"{timeout_err}")
            return False
        except requests.RequestException as err:
            self._logger.error(
                f"Generic error occurred while activating new factor {factor_id} for {user_id}."
            )
            self._logger.error(f"{err}")
            return False
        except Exception as err:
            self._logger.error(
                f"An unexpected error occurred while activating new factor {factor_id} for {user_id}."
            )
            self._logger.error(f"{err}")
            return False

    ###########################################################################
    # SECTION OF CODE TO FETCH THE DEVICES FOR EACH USER
    ###########################################################################

    @property
    def users_with_devices(self) -> list:
        if self.__users_with_devices == None:
            self._logger.debug("Retreiving the devices for each user...")
            self.users_with_devices = self.__fetch_all_devices_for_all_users()
        self._logger.debug(
            f"Returning {len(self.__users_with_devices)} devices with their devices from Okta."
        )
        return self.__users_with_devices

    @users_with_devices.setter
    def users_with_devices(self, value: list) -> None:
        self._logger.debug(
            "Okta users with deviecs setter called. Setting value of users with their devices"
        )
        self.__users_with_devices: list[dict] = value

    def __fetch_all_devices_for_all_users(self) -> list[dict]:
        users: list[dict] = self.users
        self._logger.debug(f"Will retrieve devices for {len(users)} users")
        users_with_devices: list[dict] = []
        for user in users:
            user.update({"devices": self.fetch_devices_for_user(user=user)})
            users_with_devices.append(user)
        self._logger.debug(
            f"Finished retrieving {len(users_with_devices)} users and deviecs"
        )
        return users_with_devices

    #TODO Change parameters to user ID
    @rate_limit_backoff(delay=1, retries=5)
    def fetch_devices_for_user(self, user: dict) -> list[dict]:
        self._logger.debug(f"Fetching devices for user {user['id']}")

        full_url = (
            f"https://{self._okta_domain}.okta.com/api/v1/users/{user['id']}/devices"
        )

        payload = {}
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
            "User-Agent": "okta-management-framework/1.0.0",
        }

        try:
            """self._logger.debug(
                f"Sleeping for {self._OKTA_RATE_AVOID_TIMER} seconds to avoid Okta API rate limits."
            )"""
            # time.sleep(self._OKTA_RATE_AVOID_TIMER)

            response = requests.request("GET", full_url, headers=headers, data=payload)
            response.raise_for_status()
            if "error" in response.json():
                raise requests.exceptions.RequestException(
                    f"Okta response states there as an error when fetching devices for user {user['id']} ."
                )
            elif len(response.json()) == 0:
                self._logger.warning(
                    f"User {user['id']} does not have any associated devices."
                )
                return []
            elif len(response.json()) > 0:
                self._logger.debug(
                    f"Successfully fetched {len(response.json())} factors for user {user['id']}"
                )
            return response.json()

        except requests.exceptions.RequestException as req_error:
            if response.status_code == 429:
                raise OktaRateLimitExceededError
            else:
                self._logger.error(
                    f"Error occurred fetching devices for user {user['id']}"
                )
                raise req_error
        except Exception as error:
            self._logger.error(f"Error occurred fetching devices for user {user['id']}")
            raise error

    ###########################################################################
    # SECTION OF CODE TO FETCH DEVICE USERS
    # INFO THIS IS AN OLD WAY TO FIND WHAT DEVICES A USER HAS
    # INFO Since writing this, Okta introduced a new API endpoint 'users/:userid/devices
    # INFO Which will return a list of all devices for said user id
    # SECTION To get devices for each user, user new user_with_devices attribute
    ###########################################################################

    @property
    def device_users(self) -> list:
        if self.__device_users == None:
            self._logger.debug("Loading Okta user devices")
            self.device_users = self.__fetch_users_for_all_devices()
        self._logger.debug(
            f"Returning {len(self.__device_users)} devices with their devices from Okta."
        )
        return self.__device_users

    @device_users.setter
    def device_users(self, value: list) -> None:
        self._logger.debug(
            "Okta user devices setter called. Will fetch Okta user devices"
        )
        self.__device_users: list[dict] = value

    @property
    def device_users_lookup_table(self) -> list:
        if self.__device_users_lookup_table == None:
            self._logger.debug(
                "The device_users_lookup_table is empty. Will populate the table."
            )
            if self.device_users == None:
                self._logger.debug("Loading Okta device users to create lookup table")
                self.device_users = self.__fetch_users_for_all_devices()
            self.device_users_lookup_table = self.device_users
        self._logger.debug(
            f"Returning {len(self.__device_users_lookup_table)} users from Okta."
        )
        return self.__device_users_lookup_table

    @device_users_lookup_table.setter
    def device_users_lookup_table(self, value: list) -> None:
        self._logger.debug(
            "Setter for device_users_lookup_table was called. Creating dictionary where key == device['id'], value = device_user: dict"
        )
        if isinstance(value, dict):
            if all(isinstance(v, dict) for v in value.values()):
                self._logger.debug(
                    "A dictionary was provided to the device_users_lookup_table setter function. Will set device_users_lookup_table to value and return."
                )
                self.__device_users_lookup_table = value
                return
        if value == None:
            self._logger.debug(
                "Value provided to device_users_lookup_table setter was None, so returning without making table."
            )
            return
        device_users_lookup_table: dict[dict] = {}
        for device_users in value:
            if device_users["device"]["id"] not in device_users_lookup_table:
                device_users_lookup_table.update(
                    {device_users["device"]["id"]: device_users}
                )
        self.__device_users_lookup_table = device_users_lookup_table
        self._logger.debug(
            f"Created device_users_lookup_table with length {len(device_users_lookup_table)}"
        )

    @property
    def user_devices_lookup_table(self) -> list:
        if self.__user_devices_lookup_table == None:
            self._logger.debug(
                "The user_devices_lookup_table is empty. Will populate the table."
            )
            if self.device_users == None:
                self._logger.debug(
                    "Loading Okta device users to create user_devices_lookup_table"
                )
                self.device_users = self.__fetch_users_for_all_devices()
            self.user_devices_lookup_table = self.device_users
        self._logger.debug(
            f"Returning {len(self.__user_devices_lookup_table)} users from Okta."
        )
        return self.__user_devices_lookup_table

    @user_devices_lookup_table.setter
    def user_devices_lookup_table(self, value: list) -> None:
        self._logger.debug(
            "Setter for user_devices_lookup_table was called. Creating dictionary where key == device['id'], value = device_user: dict"
        )

        if isinstance(value, dict):
            if all(isinstance(v, dict) for v in value.values()):
                self._logger.debug(
                    "A dictionary was provided to the user_devices_lookup_table setter function. Will set user_devices_lookup_table to value and return."
                )
                self.__user_devices_lookup_table = value
                return

        if value == None:
            self._logger.debug(
                "Value provided to user_devices_lookup_table setter was None, so returning without making table."
            )
            return
        user_devices_lookup_table: dict[dict[dict, list]] = {}

        for user_device in value:
            for user in user_device["users"]:
                if user["user"]["id"] not in user_devices_lookup_table:
                    user_devices_lookup_table.update(
                        {
                            user["user"]["id"]: {
                                "user": user,
                                "devices": [user_device["device"]],
                            }
                        }
                    )
                else:
                    user_devices_lookup_table[user["user"]["id"]]["devices"].append(
                        user_device["device"]
                    )

        self.__user_devices_lookup_table = user_devices_lookup_table
        self._logger.debug(
            f"Created user_devices_lookup_table containing {len(user_devices_lookup_table)} users with devices"
        )

    def __fetch_users_for_all_devices(self) -> list:
        # TODO Maybe make a version of this using concurrent futures to speed up process?
        # TODO have to worry about rate limiting tho. Maybe using that set_flag() function copilot explained?
        self._logger.debug("Fetching enrolled devices for each user...")

        # Get lookup table of all users
        self._logger.debug(
            "Calling self.users_lookup_table function to retrieve list of Okta users into local scope. This will fetch from API if users are not already defined within this class instance."
        )
        users_lookup_table: list = self.users_lookup_table
        self._logger.debug(
            f"Calling self.users_lookup_table returned {len(users_lookup_table)} users in table"
        )

        # Get lookup table of all devices
        self._logger.debug(
            "Calling self.devices_lookup_table function to retrieve list of Okta devices into local scope. This will fetch from API if devices are not already defined within this class instance."
        )
        devices_lookup_table: list = self.devices_lookup_table
        self._logger.debug(
            f"Calling self.devices_lookup_table returned {len(devices_lookup_table)} devices in table"
        )

        self._logger.debug(
            "Will enumerate all devices in list and fetch current users."
        )
        device_users: list[dict] = []
        cur_index = 0
        for device_id, device in devices_lookup_table.items():
            # If the IS_TESTING flag is true and we have fetched users for
            # 50 devices, we end early just to shorten test case evaluation
            if self.__IS_TESTING and cur_index >= self.__TESTING_COUNT_THRESHOLD:
                self._logger.warning(
                    f"The IS_TESTING flag was set to True and users for {self.__TESTING_COUNT_THRESHOLD} devices have been fetched. Will break out of loop."
                )
                break
            try:
                self._logger.debug(
                    f"#{cur_index+1}/{len(devices_lookup_table.keys())}: Fetching current users for device {device_id}"
                )
                cur_index += 1

                fetched_device_users = self.__fetch_device_users(device_id=device_id)

                # Here we are going to replace the limited user profile thats provided by
                # getting the device users with the full profile for each user that
                # uses the device.
                for user in fetched_device_users:
                    try:
                        full_user_profile = self.users_lookup_table[user["user"]["id"]][
                            "profile"
                        ]
                        user["user"]["profile"] = full_user_profile
                    except KeyError as key_error:
                        self._logger.error(key_error)
                        self._logger.warning(
                            f"Could not find full user profile within users_lookup_table for user {user['user']['id']} on device {device_id}"
                        )

                device_users.append({"device": device, "users": fetched_device_users})

            except requests.exceptions.RequestException as req_error:
                self._logger.error(req_error)
            except Exception as error:
                self._logger.error(error)

        return device_users

    @validate_attrs_present
    def __fetch_device_users(self, device_id: str) -> list[dict]:
        self._logger.debug(f"Fetching users for device {device_id}")

        full_url = (
            f"https://{self._okta_domain}.okta.com/api/v1/devices/{device_id}/users"
        )

        payload = {}
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
            "User-Agent": "okta-management-framework/1.0.0",
        }

        try:
            self._logger.debug(
                f"Sleeping for {self._OKTA_RATE_AVOID_TIMER} seconds to avoid Okta API rate limits."
            )
            time.sleep(self._OKTA_RATE_AVOID_TIMER)

            response = requests.request("GET", full_url, headers=headers, data=payload)
            response.raise_for_status()
            if "error" in response.json():
                raise requests.exceptions.RequestException(
                    "Okta response states there as an error."
                )
            elif len(response.json()) == 0:
                self._logger.warning(
                    f"Device {device_id} does not have any assigned useres."
                )
            elif len(response.json()) > 0:
                self._logger.debug(
                    f"Successfully fetched {len(response.json())} users for device {device_id}"
                )
            return response.json()

        except requests.exceptions.RequestException as req_error:
            self._logger.error(f"Error occurred fetching device users for {device_id}")
            raise req_error
        except Exception as error:
            self._logger.error(f"Error occurred fetching device users for {device_id}")
            raise error

    ###########################################################################
    # SECTION OF CODE TO FETCH APPLICATIONS
    ###########################################################################

    @property
    def applications(self) -> list:
        if self.__applications == None:
            self._logger.debug("Loading Okta applications")
            self.applications = self.__fetch_applications()
        self._logger.debug(
            f"Returning {len(self.__applications)} applications from Okta."
        )
        return self.__applications

    @applications.setter
    def applications(self, value: list) -> None:
        self._logger.debug(
            "Okta applications setter called. Will fetch Okta applications"
        )
        self.__applications: list = value
        self.applications_lookup_table: dict[dict] = value

    @property
    def applications_lookup_table(self) -> list:
        if self.__applications_lookup_table == None:
            self._logger.debug(
                "The applications_lookup_table is empty. Will populate the table."
            )
            if self.applications == None:
                self._logger.debug("Loading Okta applications to create lookup table")
                self.applications = self.__fetch_applications()

            self.applications_lookup_table = self.applications
        self._logger.debug(
            f"Returning {len(self.__applications_lookup_table)} applications from Okta."
        )
        return self.__applications_lookup_table

    @applications_lookup_table.setter
    def applications_lookup_table(self, value: list) -> None:
        self._logger.debug(
            "Setter for applications_lookup_table was called. Creating dictionary where key == application['id'], value = application: dict"
        )
        if value == None:
            self._logger.debug(
                "Value provided to applications_lookup_table setter was None, so returning without making table."
            )
            return
        applications_lookup_table: dict[dict] = {}
        for application in value:
            if application["id"] not in applications_lookup_table:
                applications_lookup_table.update({application["id"]: application})
        self.__applications_lookup_table = applications_lookup_table
        self._logger.debug(
            f"Created applications_lookup_table with length {len(applications_lookup_table)}"
        )

    def fetch_application_by_id(self, app_id: str) -> dict:
        self._logger.debug(f"Will fetch application details for {app_id}")
        full_url = f"https://{self._okta_domain}.okta.com/api/v1/apps/{app_id}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        payload = {}
        try:
            response = requests.request(
                method="GET", url=full_url, headers=headers, data=payload
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    f"Okta response states there is an error when fetching details for app {app_id}."
                )

            return data

        except requests.exceptions.RequestException as req_error:
            self._logger.error(str(req_error))
            self._logger.error(
                f"An error occurred while fetching app details for app {app_id}"
            )
            raise req_error
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error(
                f"An unanticipated exception was raised when fetching app details for app {app_id}. Unable to fetch app details"
            )
            raise error

    def __fetch_applications(self, next_page_url: str = None) -> list:
        """Paginates through all Okta applications in the tenant and returns
        list object of each app dictionary object

        Args:
            next_page_url (str, optional): URL to get next page of data Defaults to None.

        Raises:
            requests.exceptions.RequestException: If requests throws an exception

        Returns:
            list: List of dictionaries, where each dict is an app object
        """
        url = f"https://{self._okta_domain}.okta.com/api/v1/apps"

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        payload = {}

        if next_page_url:
            full_url = next_page_url
        else:
            full_url = url + "?limit=1000"
            self._logger.info(
                "Fetching all Okta applications " + f"from {self._okta_domain}"
            )

        app_list = []

        try:
            response = requests.request(
                method="GET", url=full_url, headers=headers, data=payload
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    "Okta response states there is an error."
                )

            app_list += data

        except requests.exceptions.RequestException as req_error:
            self._logger.critical(str(req_error))
            self._logger.critical(
                "Error occurred fetching apps, " + "terminating script."
            )
            sys.exit(1)
        except Exception as error:
            self._logger.critical(str(error))
            self._logger.critical(
                "Error occurred fetching apps, " + "terminating script."
            )
            sys.exit(1)

        try:
            if ' rel="next"' in dict(response.headers)["link"]:
                pattern = r'<.*?;\srel="self",\s<(.*?)>;\srel="next"$'
                match = re.search(pattern, dict(response.headers)["link"])

                if match:
                    next_page_url = match.group(1)
                    self._logger.debug(
                        "URL for next page of data: " + f"{next_page_url}"
                    )
                    app_list += self.__fetch_applications(next_page_url=next_page_url)
                else:
                    self._logger.debug("No match found for next URL.")

        except KeyError:
            self._logger.warning(
                "Link not found in response headers, " + "must be all applications"
            )

        return app_list

    ###########################################################################
    # SECTION OF CODE TO FETCH AN APPLICATIONS USERS
    ###########################################################################

    def fetch_application_users(self, app_id: str, next_page_url: str = None) -> list:
        url = f"https://{self._okta_domain}.okta.com/api/v1/apps/{app_id}/users"

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        payload = {}

        if next_page_url:
            full_url = next_page_url
        else:
            full_url = url + "?limit=1000"
            self._logger.info(
                f"Fetching all users for Okta app id {app_id}"
                + f"from {self._okta_domain}"
            )

        user_list = []

        try:
            response = requests.request(
                method="GET", url=full_url, headers=headers, data=payload
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    "Okta response states there is an error."
                )

            user_list += data

        except requests.exceptions.RequestException as req_error:
            self._logger.critical(str(req_error))
            self._logger.critical(
                "Error occurred fetching apps, " + "terminating script."
            )
            sys.exit(1)
        except Exception as error:
            self._logger.critical(str(error))
            self._logger.critical(
                "Error occurred fetching apps, " + "terminating script."
            )
            sys.exit(1)

        try:
            if ' rel="next"' in dict(response.headers)["link"]:
                pattern = r'<.*?;\srel="self",\s<(.*?)>;\srel="next"$'
                match = re.search(pattern, dict(response.headers)["link"])

                if match:
                    next_page_url = match.group(1)
                    self._logger.debug(
                        "URL for next page of data: " + f"{next_page_url}"
                    )
                    user_list += self.fetch_application_users(
                        next_page_url=next_page_url
                    )
                else:
                    self._logger.debug("No match found for next URL.")

        except KeyError:
            self._logger.warning(
                "Link not found in response headers, "
                + f"must be all users for app {app_id}"
            )

        self._logger.debug(
            f"Finished fetching {len(user_list)} users that are assigned to app id {app_id}"
        )
        return user_list

    def fetch_application_users_with_full_profiles(self, app_id: str) -> list:
        self._logger.debug(f"Fetching users for application {app_id}.")
        # Retrieve list of application users
        app_users = self.fetch_application_users(app_id=app_id)

        # Create a new list that will hold each app users FULL okta user profile
        app_users_full_profiles: list = []

        # Iterate over each app user, and make API call to fetch their full profile
        for user in app_users:
            self._logger.debug(f"Retrieving full user profile for id {user['id']}")
            app_users_full_profiles.append(self.fetch_user_by_id(user_id=user["id"]))

        self._logger.debug(
            f"Finished fetching {len(app_users_full_profiles)} application users for app id {app_id} (full user profile)"
        )
        return app_users_full_profiles

    ###########################################################################
    # SECTION OF CODE TO FETCH POLICIES
    ###########################################################################

    @property
    def sign_on_policies(self) -> list:
        if self.__sign_on_policies == None:
            self._logger.debug("Loading Okta sign_on_policies")
            self.__sign_on_policies = self.__fetch_okta_policies_by_type(
                type="ACCESS_POLICY"
            )
        self._logger.debug(
            f"Returning {len(self.__sign_on_policies)} sign_on_policies from Okta."
        )
        return self.__sign_on_policies

    @sign_on_policies.setter
    def sign_on_policies(self, value: list) -> None:
        self._logger.debug(
            "Okta sign_on_policies setter called. Will fetch Okta sign_on_policies"
        )
        self.__sign_on_policies: list = value
        self.__sign_on_policies_lookup_table: dict[dict] = value

    @property
    def sign_on_policies_lookup_table(self) -> list:
        if self.__sign_on_policies_lookup_table == None:
            self._logger.debug(
                "The sign_on_policies_lookup_table is empty. Will populate the table."
            )
            if self.sign_on_policies == None:
                self._logger.debug(
                    "Loading Okta sign_on_policies to create lookup table"
                )
                self.sign_on_policies = self.__fetch_okta_policies_by_type(
                    type="ACCESS_POLICY"
                )

            self.sign_on_policies_lookup_table = self.sign_on_policies
        self._logger.debug(
            f"Returning {len(self.__sign_on_policies_lookup_table)} sign_on_policies from Okta."
        )
        return self.__sign_on_policies_lookup_table

    @sign_on_policies_lookup_table.setter
    def sign_on_policies_lookup_table(self, value: list) -> None:
        self._logger.debug(
            "Setter for sign_on_policies_lookup_table was called. Creating dictionary where key == sign_on_policy['id'], value = sign_on_policy: dict"
        )
        if value == None:
            self._logger.debug(
                "Value provided to sign_on_policies_lookup_table setter was None, so returning without making table."
            )
            return
        sign_on_policies_lookup_table: dict[dict] = {}
        for sign_on_policy in value:
            if sign_on_policy["id"] not in sign_on_policies_lookup_table:
                sign_on_policies_lookup_table.update(
                    {sign_on_policy["id"]: sign_on_policy}
                )
        self.__sign_on_policies_lookup_table = sign_on_policies_lookup_table
        self._logger.debug(
            f"Created sign_on_policies_lookup_table with length {len(sign_on_policies_lookup_table)}"
        )

    #TODO update parameter to app id
    def fetch_app_sign_on_policy(self, app_details: dict) -> dict:
        """_summary_

        Args:
            appDetails (dict): dictionary of app attributes that is fetched from
            Okta's /app API endpoint

        Returns:
            dict: App's auth policy
        """

        self._logger.debug(f"Fetching access policy details for {app_details['label']}")

        # If the app does not have the accessPolicy key for some reason, we cannot make an
        # API call to fetch it
        try:
            if "accessPolicy" not in app_details["_links"]:
                raise ValueError(
                    f"The application {app_details['label']} did not have a link to access policy"
                )
        except ValueError as value_error:
            self._logger.warning(value_error)
            raise value_error

        # Headers w/ auth token
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }

        # Empty payload
        payload = {}

        try:
            response = requests.request(
                method="GET",
                url=app_details["_links"]["accessPolicy"]["href"],
                headers=headers,
                data=payload,
                timeout=60,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as req_error:
            self._logger.error(
                f"A request error occurred when fetching access policy for {app_details['label']}"
            )
            self._logger.error(str(req_error))
            raise req_error

    #TODO update parameters to only need app id and policy id
    def update_app_sign_on_policy(
        self, application_object: dict, policy_object: dict
    ) -> bool:
        self._logger.debug(
            f"Will update app {application_object['label']} to use policy {policy_object['name']}"
        )

        full_url = f"https://{self._okta_domain}.okta.com/api/v1/apps/{application_object['id']}/policies/{policy_object['id']}"

        # Headers w/ auth token
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }

        # Empty payload
        payload = {}

        try:
            response = requests.request(
                method="PUT", url=full_url, headers=headers, data=payload, timeout=60
            )
            response.raise_for_status()
            return True

        except requests.RequestException as req_error:
            self._logger.error(
                f"A request error occurred when trying to update app {application_object['label']} to use policy {policy_object['name']}"
            )
            self._logger.error(str(req_error))
            return False

    def fetch_policy_by_id(self, policy_id: str) -> dict:
        self._logger.debug(f"Will fetch policy details for {policy_id}")
        full_url = f"https://{self._okta_domain}.okta.com/api/v1/policies/{policy_id}"

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        payload = {}
        try:
            response = requests.request(
                method="GET", url=full_url, headers=headers, data=payload
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    f"Okta response states there is an error when fetching details for policy {policy_id}."
                )

            return data

        except requests.exceptions.RequestException as req_error:
            self._logger.error(str(req_error))
            self._logger.error(
                f"An error occurred while fetching policy details for policy {policy_id}"
            )
            raise req_error
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error(
                f"An unanticipated exception was raised when fetching policy details for policy {policy_id}. Unable to fetch policy details"
            )
            raise error

    @rate_limit_backoff(retries=6)
    def get_rules_by_policy_id(self, policy_id: str) -> list:
        self._logger.debug(f"Getting all policy rules for policy id {policy_id}")
        full_url = f"https://{self._okta_domain}.okta.com/api/v1/policies/{policy_id}/rules"

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        parameters = {
            "limit": 1000
        }
        payload = {}
        try:
            response = requests.request(
                method="GET", url=full_url, headers=headers, data=payload, params=parameters
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    f"Okta response states there is an error when fetching details for policy {policy_id}."
                )

            return data

        except requests.exceptions.RequestException as req_error:
            if response.status_code == 429:
                self._logger.warning(f"Rate limit was exceed when getting rules for policy id {policy_id}. Will wait then retry")
                raise OktaRateLimitExceededError(headers = dict(response.headers))
            else:
                self._logger.error(str(req_error))
                self._logger.error(
                    f"An error occurred while getting policy rules for policy {policy_id}"
                )
                raise req_error
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error(
                f"An unanticipated exception was raised when getting policy rules for policy {policy_id}. Unable to fetch policy rules"
            )
            raise error

    def __fetch_okta_policies_by_type(
        self, type: str = "ACCESS_POLICY", next_page_url: str = None
    ) -> list:
        """Paginates through all Okta policies in the tenant and returns
        list object of each app dictionary object

        Args:
            next_page_url (str, optional): URL to get next page of data Defaults to None.

        Raises:
            requests.exceptions.RequestException: If requests throws an exception

        Returns:
            list: List of dictionaries, where each dict is an app object
        """
        self._logger.debug("Fetching Okta policies...")
        valid_policy_types: set = (
            "OKTA_SIGN_ON",
            "PASSWORD",
            "MFA_ENROLL",
            "IDP_DISCOVERY",
            "ACCESS_POLICY",
        )
        try:
            if type not in valid_policy_types:
                raise ValueError(
                    f"The value provided for policy type, {type}, is not a valid policy type. Valid types are {str(valid_policy_types)}"
                )
            self._logger.debug(f"Will fetch {type} policies from Okta.")
            url = f"https://{self._okta_domain}.okta.com/api/v1/policies?type={type}"

        except ValueError as value_error:
            self._logger.error(value_error)
            raise ValueError

        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }
        payload = {}

        if next_page_url:
            url = next_page_url
        else:
            url = url + "&limit=1000"
            self._logger.info(
                "Fetching all Okta sign_on_policies " + f"from {self._okta_domain}"
            )

        policy_list = []

        try:
            response = requests.request(
                method="GET", url=url, headers=headers, data=payload
            )
            response.raise_for_status()

            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    "Okta response states there is an error."
                )

            policy_list += data

        except requests.exceptions.RequestException as req_error:
            self._logger.error(str(req_error))
            self._logger.error(
                f"A request error occurred when fetching {type} policies from Okta"
            )
            raise req_error
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error(
                f"An unanticipated error was raised when fetching {type} policies from Okta"
            )
            raise error

        try:
            if ' rel="next"' in dict(response.headers)["link"]:
                pattern = r'<.*?;\srel="self",\s<(.*?)>;\srel="next"$'
                match = re.search(pattern, dict(response.headers)["link"])

                if match:
                    next_page_url = match.group(1)
                    self._logger.debug(
                        "URL for next page of data: " + f"{next_page_url}"
                    )
                    policy_list += self.__fetch_okta_policies_by_type(
                        next_page_url=next_page_url, type=type
                    )
                else:
                    self._logger.debug("No match found for next URL.")

        except KeyError:
            self._logger.warning(
                "Link not found in response headers, " + "must be all devices"
            )

        return policy_list

    ###########################################################################
    # SECTION OF CODE TO FETCH SYSTEM LOGS
    ###########################################################################
    @rate_limit_backoff(retries=5)
    def get_okta_system_log_events(
        self,
        since: None | str = None,
        until: None | str = None,
        filter: None | str = None,
        query: None | str = None,
        next_page_url: None | str = None,
    ) -> list:
        """Function used to retrieve Okta system logs. You can provide several parameters to filter logs and time period

        Args:
            since (None | str, optional): An ISO8601 timestamp string - Get logs from this timestamp onwards. Defaults to None.
            until (None | str, optional): An ISO8601 timestamp string - Get logs until this timestamp. Defaults to None.
            filter (None | str, optional): A filter string to filter the logs returned by. Defaults to None.
            query (None | str, optional): A query string to query logs by (read Okta dev docs for more). Defaults to None.
            next_page_url (None | str, optional): Used internally by the function if recusrive pagination is needed. Defaults to None.

        Raises:
            requests.exceptions.RequestException: Catches an exception raised by the requests module
            OktaRateLimitExceededError: If a request exception is raised due to rate limit exceeded, this is raised.
            req_error: If the request exception was not rate limit related, the original request exception is raised further
            error: Catches a generic exception that was unhandled elsewhere and raises it further

        Returns:
            list: List of events from the Okta system log
        """
        headers = {
            "Accept": "application/json",
            "Authorization": f"SSWS {self.__api_token}",
        }

        payload = {}

        log_event_list: list = []

        try:
            if next_page_url:
                self._logger.info("An additional page of logs are being retrieved...")
                self._logger.debug(f"Next page URL was set: {next_page_url}")
                url = next_page_url
                response = requests.request(
                    method="GET", url=url, headers=headers, data=payload
                )
            else:
                self._logger.info("Fetching Okta system event logs...")
                url = f"https://{self._okta_domain}.okta.com/api/v1/logs"
                self._logger.debug("Next page URL not set, using base URL:")
                params = {"limit": 1000}
                if since:
                    self._logger.debug(
                        f"The since parameter was provided and will be added to params: {since}"
                    )
                    params.update({"since": since})
                if until:
                    self._logger.debug(
                        f"The until parameter was provided and will be added to params: {until}"
                    )
                    params.update({"until": until})
                if filter:
                    self._logger.debug(
                        f"The filter parameter was provided and will be added to params: {filter}"
                    )
                    params.update({"filter": filter})
                if query:
                    self._logger.debug(
                        f"The query parameter was provided and will be added to params: {query}"
                    )
                    params.update({"query": query})
                self._logger.debug(
                    f"Retreiving Okta system logs with the following parameters: {str(params)}"
                )
                response = requests.request(
                    method="GET", url=url, headers=headers, data=payload, params=params
                )

            response.raise_for_status()
            data = response.json()

            if "error" in data:
                raise requests.exceptions.RequestException(
                    "Okta response states there is an error."
                )

            log_event_list += data

        except requests.exceptions.RequestException as req_error:
            if response.status_code == 429:
                self._logger.warning("Rate limit was exceeded.")
                self._logger.debug(req_error)
                raise OktaRateLimitExceededError(
                    message="Rate limit exceeded while retrieving system logs",
                    headers=dict(response.headers),
                )
            else:
                self._logger.error(str(req_error))
                self._logger.error(
                    "A generic request error occurred when fetching system log events from Okta"
                )
                raise req_error
        except Exception as error:
            self._logger.error(str(error))
            self._logger.error(
                f"An unanticipated error was raised when fetching {type} system log events from Okta"
            )
            raise error

        # Check if pagination is needed and recurse if so
        try:
            if ' rel="next"' in dict(response.headers)["link"]:
                pattern = r'<.*?;\srel="self",\s<(.*?)>;\srel="next"$'
                match = re.search(pattern, dict(response.headers)["link"])

                if match:
                    next_page_url = match.group(1)
                    self._logger.debug(
                        "URL for next page of data: " + f"{next_page_url}"
                    )
                    log_event_list += self.get_okta_system_log_events(
                        next_page_url=next_page_url
                    )
                else:
                    self._logger.debug("No match found for next URL.")

        except KeyError as ke:
            self._logger.warning(
                "Link not found in response headers, end of paging reached."
            )
        except TypeError as te:
            self._logger.warning(f"Type error was raised while getting okta system log events: {te}")

        return log_event_list
