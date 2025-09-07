from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()


class RegistrationData(models.Model):
    """
    Store registration data from Regfox webhooks.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="registration_data"
    )

    # Registration identifiers
    regfox_order_id = models.CharField(max_length=100, blank=True)
    regfox_registrant_id = models.CharField(max_length=100, blank=True)
    regfox_order_number = models.CharField(max_length=100, blank=True)
    regfox_customer_id = models.CharField(max_length=100, blank=True)

    # Registration status
    registration_status = models.CharField(max_length=50, default="pending")

    # Raw webhook data for debugging/reference
    raw_registration_data = models.JSONField(default=dict, blank=True)
    raw_billing_data = models.JSONField(default=dict, blank=True)

    # Timestamps
    registration_timestamp = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Registration Data"
        verbose_name_plural = "Registration Data"

    def __str__(self):
        return f"Registration for {self.user} ({self.regfox_order_number})"


class WebhookLog(models.Model):
    """
    Log webhook events for debugging and audit purposes.
    """

    delivery_id = models.CharField(max_length=100)
    event_type = models.CharField(max_length=50)

    # Request data
    headers = models.JSONField(default=dict)
    payload = models.JSONField(default=dict)

    # Processing results
    processing_result = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=20, default="received")
    error_message = models.TextField(blank=True)

    # Timestamps
    received_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Webhook Log"
        verbose_name_plural = "Webhook Logs"
        ordering = ["-received_at"]

    def __str__(self):
        return f"{self.event_type} - {self.delivery_id} ({self.status})"
