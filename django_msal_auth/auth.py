"""Authentication backend for Microsoft Identity Platform using MSAL."""

import base64
import json

import msal
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import ObjectDoesNotExist
from django.core.signing import dumps
from django.http import HttpRequest
from django.middleware.csrf import get_token

from .exceptions import MSALTokenError

client_app = msal.ConfidentialClientApplication(
    client_id=settings.MSAL_AUTH["client_id"],
    client_credential=settings.MSAL_AUTH["client_secret"],
    authority=f"https://login.microsoftonline.com/{settings.MSAL_AUTH['tenant_id'] or 'common'}",
)

UserModel = get_user_model()


def construct_msal_login_url(request: HttpRequest):
    """
    Construct the redirect URL for MSAL authentication.

    Args:
        request: Current HTTP request object.

    Returns:
        Redirect URL string.
    """
    # Get the next url from query string if present
    next_url = request.GET.get("next")

    # Grab a CSRF Token and use it for state validation
    state = {"token": get_token(request)}

    # Set next url in the state if there is one
    if next_url:
        state["next"] = next_url

    # Build our callback (redirect) URL that will be used once authenticated
    redirect_url = f"{request.scheme}://{settings.MSAL_AUTH['site_domain']}/microsoft/from-auth-redirect/"

    # Sign our state with our Django SECRET_KEY
    signed_state = dumps(state, salt=settings.SECRET_KEY)

    # Create the full Auth url for Microsoft Authentication
    auth_flow = client_app.initiate_auth_code_flow(
        scopes=settings.MSAL_AUTH["scopes"], state=signed_state, redirect_uri=redirect_url
    )

    # Save to Session for use with callback getting Access Token
    request.session["auth_flow"] = auth_flow
    return auth_flow


def get_access_token(request: HttpRequest):
    result = client_app.acquire_token_by_auth_code_flow(
        auth_code_flow=request.session.get("auth_flow", {}), auth_response=request.GET
    )

    if "access_token" in result:
        return result["access_token"]

    raise MSALTokenError(f"{result.get('error')} : {result.get('error_description')}")


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
            if "access_token" in kwargs:
                access_token = kwargs["access_token"]
                payload = json.loads(
                    base64.b64decode(access_token.split(".")[1] + "===")
                )  # The '===' prevents Invalid Padding issue

                # Attempt to get the user by object id, or create a new user

                try:
                    user = UserModel.objects.get(username=payload["oid"])
                except ObjectDoesNotExist:
                    email = payload.get("email", payload.get("upn", ""))
                    user = UserModel(
                        username=payload["oid"],
                        email=email,
                        first_name="Unknown",
                        last_name="Unknown",
                    )

                # Populate names if available
                if "given_name" in payload.keys():
                    user.first_name = payload["given_name"]
                if "family_name" in payload.keys():
                    user.last_name = payload["family_name"]

                # Save user
                user.save()

        return user

    def get_user(self, user_id):
        try:
            return UserModel.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None
