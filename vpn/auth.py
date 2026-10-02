"""Login with brute-force throttling and a forced change of the bootstrap password."""
import hashlib

from django.conf import settings
from django.contrib.auth import views as auth_views
from django.core.cache import cache

from .middleware import FORCE_CHANGE_KEY
from .models import AuditLog

IP_FACTOR = 4  # one IP may fail this many times more across all usernames


def client_ip(request):
    if settings.BEHIND_PROXY:
        # Set by our nginx config; not spoofable because nginx overwrites it.
        return request.META.get("HTTP_X_REAL_IP") or request.META.get("REMOTE_ADDR", "")
    return request.META.get("REMOTE_ADDR", "")


def _keys(request, username):
    ip = client_ip(request)
    user_hash = hashlib.sha256(f"{ip}|{username.lower()}".encode()).hexdigest()
    return f"login-fail:ip:{ip}", f"login-fail:user:{user_hash}"


class ThrottledLoginView(auth_views.LoginView):
    def _locked(self, request):
        ip_key, user_key = _keys(request, request.POST.get("username", ""))
        limit = settings.LOGIN_MAX_FAILURES
        return cache.get(user_key, 0) >= limit or cache.get(ip_key, 0) >= limit * IP_FACTOR

    def post(self, request, *args, **kwargs):
        if self._locked(request):
            # Do not even check the password while locked.
            return self.render_to_response(self.get_context_data(
                form=self.get_form_class()(request),
                locked_message=f"Too many failed logins. Try again in {settings.LOGIN_LOCK_SECONDS // 60} minutes.",
            ))
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        ip_key, user_key = _keys(self.request, self.request.POST.get("username", ""))
        for key in (ip_key, user_key):
            cache.add(key, 0, settings.LOGIN_LOCK_SECONDS)
            try:
                cache.incr(key)
            except ValueError:
                cache.set(key, 1, settings.LOGIN_LOCK_SECONDS)
        AuditLog.record(None, "login.failed", self.request.POST.get("username", "")[:150],
                        f"from {client_ip(self.request)}", success=False)
        return super().form_invalid(form)

    def form_valid(self, form):
        _, user_key = _keys(self.request, form.get_user().get_username())
        cache.delete(user_key)
        response = super().form_valid(form)
        if form.cleaned_data.get("password") == settings.PRIVATEVPN_DEFAULT_ADMIN_PASSWORD:
            self.request.session[FORCE_CHANGE_KEY] = True
        AuditLog.record(self.request.user, "login", self.request.user.username, f"from {client_ip(self.request)}")
        return response
