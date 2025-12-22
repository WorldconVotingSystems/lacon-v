from django.contrib.sessions.models import Session
from django.db import models

import logging

logger = logging.getLogger(__name__)


class OIDCSessionMappingManager(models.Manager):
    """Custom manager for OIDCSessionMapping with session termination logic"""

    def terminate_sessions_for_sid(self, sid: str) -> int:
        """Terminate all Django sessions associated with an OIDC session ID. Returns count."""
        mappings = self.filter(sid=sid)
        session_keys = [m.session_key for m in mappings]

        logger.info(
            f"Terminating sessions for sid={sid}, found {len(session_keys)} mappings: {session_keys}"
        )

        # Check if these sessions actually exist
        existing_sessions = Session.objects.filter(session_key__in=session_keys)
        existing_keys = [s.session_key for s in existing_sessions]
        logger.info(
            f"Found {len(existing_keys)} matching sessions in DB: {existing_keys}"
        )

        deleted_count = existing_sessions.delete()[0]
        mappings.delete()

        logger.info(f"Deleted {deleted_count} sessions")
        return deleted_count


class OIDCSessionMapping(models.Model):
    """Maps OIDC session IDs (sid) to Django session keys for back-channel logout"""

    sid = models.CharField(max_length=255, db_index=True, unique=False)
    session_key = models.CharField(max_length=40, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = OIDCSessionMappingManager()

    class Meta:
        indexes = [
            models.Index(fields=["sid"]),
            models.Index(fields=["session_key"]),
        ]
