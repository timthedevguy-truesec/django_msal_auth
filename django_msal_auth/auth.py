"""Authentication backend for Microsoft Identity Platform using MSAL."""

import base64
import json

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import ObjectDoesNotExist

from . import util

UserModel = get_user_model()


class MicrosoftAuthenticationBackend(BaseBackend):
    """
    Authentication backend that uses the MSAL python library to access the new
    Microsoft Identity Platform
    """

    def authenticate(self, request, **kwargs):
        """
        Authenticate the user and return a valid user object
        :param request:
        :param kwargs: claims
        :return: User | None
        """
        user = None

        # if kwargs contains the password field than this is a local login, support
        # ability to keep local login around.
        if "password" not in kwargs:
            # Get Access Token from MS, this validates the user is still
            # able to login
            token_request = util.get_msal_token(request)
            # Sanity check on result
            if token_request is not None:
                # Ensure we have an Access Token
                if "access_token" in token_request:
                    # Decode the payload
                    at_payload = token_request["access_token"].split(".")[1]
                    at_payload = base64.b64decode(
                        at_payload + "==="
                    )  # The '===' prevents Invalid Padding issue
                    at_payload = json.loads(at_payload)

                    # Attempt to get the user by object id, or create a new user

                    try:
                        user = UserModel.objects.get(username=at_payload["oid"])
                    except ObjectDoesNotExist:
                        user = UserModel(
                            username=at_payload["oid"],
                            email=at_payload["upn"],
                            first_name="Unknown",
                            last_name="Unknown",
                        )

                    # Populate names if available
                    if "given_name" in at_payload.keys():
                        user.first_name = at_payload["given_name"]
                    if "family_name" in at_payload.keys():
                        user.last_name = at_payload["family_name"]

                    # Save user
                    user.save()

        return user

    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None
