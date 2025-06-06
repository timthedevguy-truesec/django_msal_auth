"""Utility module for msal token and cache management."""

import msal
from django.conf import settings
from django.core.signing import dumps
from django.http import HttpRequest
from django.middleware.csrf import get_token


def build_msal_app(cache=None):
    """
    Build and return an MSAL ConfidentialClientApplication instance.

    Args:
        cache: MSAL cache to use for token storage. If None, a new cache will be created.

    Returns:
        ConfidentialClientApplication instance.
    """
    authority_target = settings.MSAL_AUTH["tenant_id"] or "common"
    return msal.ConfidentialClientApplication(
        client_id=settings.MSAL_AUTH["client_id"],
        client_credential=settings.MSAL_AUTH["client_secret"],
        authority=f"https://login.microsoftonline.com/{authority_target}",
        token_cache=cache,
    )


def load_msal_cache(request):
    """
    Load the MSAL token cache from the session.
    Args:
        request: Current HTTP request object.

    Returns:
        Token cache instance.
    """
    cache = msal.SerializableTokenCache()
    if request.session.get("token_cache"):
        cache.deserialize(request.session.get("token_cache", msal.SerializableTokenCache()))

    return cache


def save_msal_cache(request, cache):
    """
    Save the MSAL token cache to the session.
    Args:
        request: Current HTTP request object.
        cache: Current MSAL token cache instance.
    """
    if cache.has_state_changed:
        request.session["token_cache"] = cache.serialize()


def get_msal_token(request):
    """
    Get the MSAL access token for the current user.
    Args:
        request: Current HTTP request object.

    Returns:
        Token dictionary containing access token and other details, or None if not available.
    """
    cache = load_msal_cache(request)
    msal_app = build_msal_app(cache)
    accounts = msal_app.get_accounts()

    return msal_app.acquire_token_silent(settings.MSAL_AUTH["scopes"], account=accounts[0])


def construct_url(request: HttpRequest):
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
    auth_details = build_msal_app().initiate_auth_code_flow(
        scopes=settings.MSAL_AUTH["scopes"], state=signed_state, redirect_uri=redirect_url
    )

    return auth_details["auth_uri"]
