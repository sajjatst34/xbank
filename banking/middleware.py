"""
X Bank - Security Middleware
Handles security headers, session timeout, and request logging.
"""
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger('banking')


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Add security headers to every response."""

    def process_response(self, request, response):
        # Content Security Policy
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: blob:; "
            "connect-src 'self';"
        )
        # Anti-clickjacking
        response['X-Frame-Options'] = 'DENY'
        # Prevent MIME sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        # XSS protection
        response['X-XSS-Protection'] = '1; mode=block'
        # Referrer policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Permissions policy
        response['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
        # Cache control for sensitive pages
        if request.user.is_authenticated:
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
        return response


class SessionTimeoutMiddleware(MiddlewareMixin):
    """Auto-logout users after SESSION_COOKIE_AGE seconds of inactivity."""

    def process_request(self, request):
        if not request.user.is_authenticated:
            return None

        last_activity = request.session.get('last_activity')
        now = timezone.now().timestamp()

        if last_activity:
            elapsed = now - last_activity
            timeout = getattr(settings, 'SESSION_COOKIE_AGE', 1800)
            if elapsed > timeout:
                logger.info(
                    f"Session timeout for user {request.user.username} "
                    f"after {elapsed:.0f}s inactivity"
                )
                logout(request)
                messages.warning(
                    request,
                    'Your session has expired due to inactivity. Please log in again.'
                )
                return redirect('banking:login')

        request.session['last_activity'] = now
        return None


class RequestLoggingMiddleware(MiddlewareMixin):
    """Log all requests for audit trail (only for banking endpoints)."""

    SENSITIVE_PATHS = ['/transfer/', '/withdraw/', '/deposit/', '/card/']

    def process_request(self, request):
        if any(request.path.startswith(p) for p in self.SENSITIVE_PATHS):
            if request.user.is_authenticated:
                logger.info(
                    f"SENSITIVE_REQUEST user={request.user.username} "
                    f"method={request.method} path={request.path} "
                    f"ip={get_client_ip(request)}"
                )


def get_client_ip(request):
    """Extract real client IP, handling proxies."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')
