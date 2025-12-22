"""OIDC logout views for LAcon V"""

# Standard library
import logging
from typing import Any

# Third-party
import jwt
from jwt import PyJWKClient

# Django
from django.conf import settings
from django.contrib.auth import logout as django_logout
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

# Local
from lacon_v_app.models import OIDCSessionMapping

logger = logging.getLogger(__name__)


def _validate_logout_token(token: str) -> dict[str, Any]:
    signing_key = PyJWKClient(
        settings.SOCIAL_AUTH_LACON_JWKS_URI
    ).get_signing_key_from_jwt(token)

    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.SOCIAL_AUTH_LACON_KEY,
        issuer=settings.SOCIAL_AUTH_LACON_OIDC_ENDPOINT,
        options={"require": ["iss", "aud", "iat", "jti", "events"]},
    )

    events = claims.get("events", {})
    if "http://schemas.openid.net/event/backchannel-logout" not in events:
        raise jwt.InvalidTokenError("Not a logout token")
    if "sid" not in claims and "sub" not in claims:
        raise jwt.InvalidTokenError("Logout token must contain sid or sub")
    if "nonce" in claims:
        raise jwt.InvalidTokenError("Logout token must not contain nonce")

    return claims


@csrf_exempt
@require_POST
def backchannel_logout(request: HttpRequest) -> HttpResponse:
    """
    Handle back-channel logout requests from Authentik.

    Authentik posts a logout_token JWT when a user's session is terminated.
    We validate the token and terminate matching Django sessions.
    """
    logout_token = request.POST.get("logout_token")

    if not logout_token:
        logger.warning("Back-channel logout request missing logout_token")
        return HttpResponse("Missing logout_token", status=400)

    try:
        claims = _validate_logout_token(logout_token)

        # Extract sid or sub
        sid = claims.get("sid")
        sub = claims.get("sub")

        logger.info(f"Back-channel logout: sid={sid}, sub={sub}")

        # Terminate sessions by sid if present
        sessions_terminated = 0
        if sid:
            sessions_terminated = OIDCSessionMapping.objects.terminate_sessions_for_sid(
                sid
            )
        elif sub:
            # If only sub is provided, terminate all sessions for that user
            from social_django.models import UserSocialAuth
            from django.contrib.sessions.models import Session

            try:
                social_auth = UserSocialAuth.objects.get(provider="lacon", uid=sub)
                user = social_auth.user
                # Terminate all sessions for this user
                user_sessions = Session.objects.all()
                for session in user_sessions:
                    data = session.get_decoded()
                    if data.get("_auth_user_id") == str(user.id):
                        session.delete()
                        sessions_terminated += 1
            except UserSocialAuth.DoesNotExist:
                logger.warning(f"Back-channel logout: user not found for sub={sub}")

        logger.info(f"Back-channel logout: terminated {sessions_terminated} sessions")
        return HttpResponse(status=200)

    except jwt.PyJWTError as e:
        logger.error(f"Back-channel logout: invalid token: {e}")
        return HttpResponse("Invalid logout_token", status=400)
    except Exception as e:
        logger.error(f"Back-channel logout: error: {e}", exc_info=True)
        return HttpResponse("Internal error", status=500)


def rp_initiated_logout(request: HttpRequest) -> HttpResponse:
    """
    OIDC relying-party initiated logout: Clear local session and redirect to Authentik session invalidation.
    """

    # Clear local Django session
    django_logout(request)

    return redirect(settings.SOCIAL_AUTH_LACON_INVALIDATION_ENDPOINT)
