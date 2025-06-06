from django import template

from django_msal_auth.auth import construct_msal_login_url

register = template.Library()


@register.simple_tag(takes_context=True)
def msal_auth_url(context):
    """
    Returns the MSAL authentication URL for the current request context.

    Args:
        context: The template context containing the request.

    Returns:
        str: The MSAL authentication URL.
    """
    request = context["request"]
    auth_flow = construct_msal_login_url(request)
    return auth_flow["auth_uri"]
