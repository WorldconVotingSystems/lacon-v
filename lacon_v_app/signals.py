import logging

from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from .models import OIDCSessionMapping

logger = logging.getLogger(__name__)


@receiver(user_logged_in)
def create_oidc_session_mapping(sender, request, user, **kwargs):  # type: ignore[no-untyped-def]
    """
    After a successful login, record a mapping from OIDC sid -> Django session_key.
    """
    # During social-auth pipeline the session key can be missing or rotated
    # by Django's login() (which calls cycle_key()). Grabbing it post-login
    # ensures we persist the final key stored in the session cookie and database.
    try:
        # Retrieve sid stashed by the social-auth pipeline for this login
        if not hasattr(request, "session"):
            return
        sid = request.session.get("oidc_sid")
        if not sid:
            # No OIDC sid for this login; nothing to map
            return

        session_key = request.session.session_key
        if not session_key:
            logger.warning("OIDC mapping skipped: no session_key available post-login")
            return

        OIDCSessionMapping.objects.create(sid=sid, session_key=session_key)
        logger.info("Created OIDC mapping: sid=%s -> session=%s", sid, session_key)
    except Exception:
        logger.exception("Error creating OIDC session mapping on user_logged_in")
