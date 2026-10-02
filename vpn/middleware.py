from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse

FORCE_CHANGE_KEY = "privatevpn_must_change_password"


class ForcePasswordChangeMiddleware:
    """Keep anyone who logged in with the bootstrap password on the password page."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if (
            request.user.is_authenticated
            and request.session.get(FORCE_CHANGE_KEY)
            and request.path not in (reverse("password_change"), reverse("logout"))
            and not request.path.startswith("/static/")
        ):
            messages.warning(request, "You are using the default password. Choose a new one to continue.")
            return redirect("password_change")
        return self.get_response(request)
