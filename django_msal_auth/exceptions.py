class MSALStateInvalidError(Exception):
    """Exception raised when the MSAL state is invalid."""

    pass


class MSALTokenError(Exception):
    """Exception raised when there is an error getting the MSAL token."""

    pass
