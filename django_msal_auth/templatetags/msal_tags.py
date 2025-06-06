from django import template

from django_msal_auth import util

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
    return util.construct_url(request)
