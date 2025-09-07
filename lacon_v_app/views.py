import hashlib
import hmac
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.transaction import atomic, non_atomic_requests
from django.http import HttpResponse, HttpResponseBadRequest
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import RegistrationData, WebhookLog

logger = logging.getLogger(__name__)
User = get_user_model()

# Configuration
REGFOX_WEBHOOK_PAYLOAD_LOG_DIR_str = getattr(
    settings, "REGFOX_WEBHOOK_PAYLOAD_LOG_DIR", None
)
if REGFOX_WEBHOOK_PAYLOAD_LOG_DIR_str:
    REGFOX_WEBHOOK_PAYLOAD_LOG_DIR = Path(REGFOX_WEBHOOK_PAYLOAD_LOG_DIR_str)
    REGFOX_WEBHOOK_PAYLOAD_LOG_DIR.mkdir(parents=True, exist_ok=True)
else:
    REGFOX_WEBHOOK_PAYLOAD_LOG_DIR = None

WEBHOOK_SECRET = getattr(settings, "REGFOX_WEBHOOK_SECRET", None)


@csrf_exempt
@non_atomic_requests
@require_http_methods(["POST"])
def regfox_webhook(request):
    """
    Handle webhooks from RegFox for registration events.

    Initially logs all payloads to JSON files for debugging, with stubs for
    user creation/updates based on registration data.
    """
    try:
        # Parse the incoming payload
        payload = json.loads(request.body.decode("utf-8"))

        # Get webhook headers
        delivery_id = request.headers.get("X-Webconnex-Delivery", "unknown")
        event_type = request.headers.get("X-Webconnex-Event", "unknown")
        signature = request.headers.get("X-Webconnex-Signature", "")

        # Verify webhook signature if secret is configured
        if WEBHOOK_SECRET and not _verify_signature(
            request.body, signature, WEBHOOK_SECRET
        ):
            logger.warning(f"Invalid webhook signature for delivery {delivery_id}")
            return HttpResponseBadRequest(b"Invalid signature")

        # Save webhook log to database
        webhook_log = WebhookLog.objects.create(  # type: ignore
            delivery_id=delivery_id,
            event_type=event_type,
            headers=dict(request.headers),
            payload=payload,
            status="processing",
        )

        # Log the payload to JSON file (for debugging)
        log_file = _log_webhook_payload(payload, delivery_id, event_type)

        try:
            # Process the webhook based on event type
            result = _process_webhook_event(payload, event_type)

            # Update webhook log with success
            webhook_log.processing_result = result
            webhook_log.status = "processed"
            webhook_log.processed_at = timezone.now()
            webhook_log.save()

            logger.info(
                f"Processed webhook {event_type} (delivery: {delivery_id}) -> {log_file}"
            )

            return HttpResponse(
                json.dumps({"status": "success", "processed": result}).encode("utf-8"),
                content_type="application/json",
            )
        except Exception as e:
            # Update webhook log with error
            webhook_log.status = "error"
            webhook_log.error_message = str(e)
            webhook_log.processed_at = timezone.now()
            webhook_log.save()
            raise

        return HttpResponse(
            json.dumps({"status": "success", "processed": result}).encode("utf-8"),
            content_type="application/json",
        )

    except json.JSONDecodeError:
        logger.error("Invalid JSON in webhook payload")
        return HttpResponseBadRequest(b"Invalid JSON")
    except Exception as e:
        logger.error(f"Error processing webhook: {e}")
        return HttpResponseBadRequest(b"Webhook processing failed")


def _verify_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify the webhook signature using HMAC-SHA256."""
    if not signature or not secret:
        return False

    expected_signature = hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(signature, expected_signature)


def _log_webhook_payload(
    payload: dict, delivery_id: str, event_type: str
) -> Path | None:
    """Log webhook payload to a JSON file for debugging."""
    if not REGFOX_WEBHOOK_PAYLOAD_LOG_DIR:
        return None

    timestamp = datetime.now().isoformat()
    filename = f"{timestamp}_{event_type}_{delivery_id}.json"
    log_file = REGFOX_WEBHOOK_PAYLOAD_LOG_DIR / filename

    log_data = {
        "timestamp": timestamp,
        "delivery_id": delivery_id,
        "event_type": event_type,
        "payload": payload,
    }

    with open(log_file, "w") as f:
        json.dump(log_data, f, indent=2)

    return log_file


@atomic
def _process_webhook_event(payload: Dict[str, Any], event_type: str) -> Dict[str, Any]:
    """
    Process webhook events and return processing result.

    Currently contains stubs for user creation/update based on registration data.
    """
    result: Dict[str, Any] = {"event_type": event_type, "actions": []}

    if event_type == "registration":
        result.update(_handle_registration_event(payload))
    elif event_type == "subscription":
        result.update(_handle_subscription_event(payload))
    elif event_type in ["registrant_edit", "registrant_cancel"]:
        result.update(_handle_registrant_update_event(payload))
    else:
        result["actions"].append(f"Unhandled event type: {event_type}")

    return result


def _handle_registration_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle new registration events.

    Creates or updates user based on registration data.
    """
    result: Dict[str, Any] = {"actions": []}

    try:
        data = payload.get("data", {})
        billing = data.get("billing", {})

        # Extract user information
        email = billing.get("email")
        name = billing.get("name", {})
        first_name = name.get("first", "")
        last_name = name.get("last", "")

        if email:
            # Create or update user
            user, created = User.objects.get_or_create(  # type: ignore
                email=email,
                defaults={
                    "username": email,
                    "first_name": first_name,
                    "last_name": last_name,
                },
            )

            if not created:
                # Update existing user information
                user.first_name = first_name or user.first_name
                user.last_name = last_name or user.last_name
                user.save()
                result["actions"].append(f"Updated existing user: {email}")
            else:
                result["actions"].append(f"Created new user: {email}")

            # Create or update registration data
            registration_data, reg_created = RegistrationData.objects.get_or_create(  # type: ignore
                user=user,
                defaults={
                    "regfox_order_id": data.get("id", ""),
                    "regfox_order_number": data.get("orderNumber", ""),
                    "regfox_customer_id": str(data.get("customerId", "")),
                    "registration_status": data.get("orderStatus", "pending"),
                    "raw_registration_data": data,
                    "raw_billing_data": billing,
                },
            )

            if not reg_created:
                # Update existing registration data
                registration_data.regfox_order_id = data.get(
                    "id", registration_data.regfox_order_id
                )
                registration_data.regfox_order_number = data.get(
                    "orderNumber", registration_data.regfox_order_number
                )
                registration_data.regfox_customer_id = str(
                    data.get("customerId", registration_data.regfox_customer_id)
                )
                registration_data.registration_status = data.get(
                    "orderStatus", registration_data.registration_status
                )
                registration_data.raw_registration_data = data
                registration_data.raw_billing_data = billing
                registration_data.save()
                result["actions"].append("Updated registration data")
            else:
                result["actions"].append("Created new registration data")

            # Parse registration timestamp if available
            if "registrationTimestamp" in data:
                try:
                    reg_timestamp = datetime.fromisoformat(
                        data["registrationTimestamp"].replace("Z", "+00:00")
                    )
                    registration_data.registration_timestamp = reg_timestamp
                    registration_data.save()
                except (ValueError, AttributeError):
                    result["actions"].append("Could not parse registration timestamp")

            result["user_id"] = user.id
            result["user_email"] = email
        else:
            result["actions"].append("No email found in registration data")

    except Exception as e:
        result["actions"].append(f"Error processing registration: {e}")

    return result


def _handle_subscription_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle subscription/recurring payment events.

    TODO: Implement subscription processing logic.
    """
    result: Dict[str, Any] = {"actions": []}

    try:
        data = payload.get("data", {})
        billing = data.get("billing", {})
        subscription = data.get("subscription", {})

        email = billing.get("email")
        if email:
            result["actions"].append(f"Would process subscription for: {email}")
            result["subscription_data"] = subscription
        else:
            result["actions"].append("No email found in subscription data")

    except Exception as e:
        result["actions"].append(f"Error processing subscription: {e}")

    return result


def _handle_registrant_update_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle registrant edit/cancel events.

    TODO: Implement user update/cancellation logic.
    """
    result: Dict[str, Any] = {"actions": []}

    try:
        data = payload.get("data", {})

        # Extract relevant information for user updates
        registrant_id = data.get("id")
        status = data.get("status")

        if registrant_id:
            result["actions"].append(
                f"Would update registrant {registrant_id} with status: {status}"
            )
            result["update_data"] = data
        else:
            result["actions"].append("No registrant ID found in update data")

    except Exception as e:
        result["actions"].append(f"Error processing registrant update: {e}")

    return result
