"""Django views for MSAL authentication."""

import logging
import re

from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.core.signing import BadSignature, SignatureExpired, loads
from django.http import HttpRequest
from django.middleware.csrf import CSRF_TOKEN_LENGTH
from django.shortcuts import redirect

from . import util
from .exceptions import MSALStateInvalidError, MSALTokenError

logger = logging.getLogger("django")


def to_auth_redirect(request):
    """
    View that redirects the user to Microsoft for authentication.
    Args:
        request: Current HTTP request object.

    Returns:
        Redirect to Microsoft authentication URL.
    """
    return redirect(util.construct_url(request))


def from_auth_redirect(request: HttpRequest):
    """
    View that handles the redirect from Microsoft after authentication.
    Args:
        request: Current HTTP request object.

    Returns:
        Redirect to the next URL or login page if authentication fails.
    """
    # Get State and perform sanity check
    state = request.GET.get("state")
    if state is None:
        state = ""

    try:
        # Check signature of the state using Django SECRET_KEY
        state = loads(state, salt=settings.SECRET_KEY, max_age=300)
    except SignatureExpired:
        raise MSALStateInvalidError("Signature has expired")
    except BadSignature:
        raise MSALStateInvalidError("State has been tampered with")

    # Get the CSRF token and verify it
    token = state.get("token", "")
    # Build array of conditions to meet
    checks = (
        re.search("[a-zA-Z0-9]", token),
        len(token) == CSRF_TOKEN_LENGTH,
    )

    # Check all conditions
    if not all(checks):
        raise MSALStateInvalidError("State failed validation checks")

    # Create default next URL and pull one from state if present
    next_url = "/"
    if "next" in state:
        next_url = state["next"]

    # Build redirect url
    redirect_url = f"{request.scheme}://{settings.MSAL_AUTH['site_domain']}/microsoft/from-auth-redirect/"

    # Use Microsoft MSAL Library to get the resultant tokens
    cache = util.load_msal_cache(request)
    result = util.build_msal_app(cache).acquire_token_by_authorization_code(
        code=request.GET.get("code"), scopes=settings.MSAL_AUTH["scopes"], redirect_uri=redirect_url
    )

    # Check for an error in results
    if "error" in result:
        raise MSALTokenError(result["error"])

    # Get ID Token so we can grab the claims
    token_claims = result.get("id_token_claims")
    util.save_msal_cache(request, cache)

    # Create/Get our user based on the request and claims
    user = authenticate(request, claims=token_claims)

    # Sanity check the User
    if user:
        # Login the user
        login(request, user)
        # Redirect user to original page
        return redirect(next_url)

    return redirect(settings.LOGIN_REDIRECT_URL)


def signout(request):
    """
    Signs out the user and clears the session token cache.
    Args:
        request: Current HTTP request object.

    Returns:
        Redirect to Microsoft logout URL.
    """
    try:
        del request.session["token_cache"]
    except KeyError:
        pass

    logout(request)

    return redirect("https://login.microsoftonline.com/common/oauth2/v2.0/logout")
