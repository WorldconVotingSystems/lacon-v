from django.contrib import admin
from .models import RegistrationData, WebhookLog


@admin.register(RegistrationData)
class RegistrationDataAdmin(admin.ModelAdmin):
    list_display = [
        "user",
        "regfox_order_number",
        "registration_status",
        "registration_timestamp",
        "updated_at",
    ]
    list_filter = ["registration_status", "created_at", "updated_at"]
    search_fields = [
        "user__email",
        "user__first_name",
        "user__last_name",
        "regfox_order_number",
        "regfox_customer_id",
    ]
    readonly_fields = ["created_at", "updated_at"]

    fieldsets = (
        ("User", {"fields": ("user",)}),
        (
            "RegFox Identifiers",
            {
                "fields": (
                    "regfox_order_id",
                    "regfox_registrant_id",
                    "regfox_order_number",
                    "regfox_customer_id",
                )
            },
        ),
        ("Status", {"fields": ("registration_status", "registration_timestamp")}),
        (
            "Raw Data",
            {
                "fields": ("raw_registration_data", "raw_billing_data"),
                "classes": ("collapse",),
            },
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(WebhookLog)
class WebhookLogAdmin(admin.ModelAdmin):
    list_display = [
        "delivery_id",
        "event_type",
        "status",
        "received_at",
        "processed_at",
    ]
    list_filter = ["event_type", "status", "received_at"]
    search_fields = ["delivery_id", "event_type"]
    readonly_fields = ["received_at", "processed_at"]

    fieldsets = (
        ("Event Info", {"fields": ("delivery_id", "event_type", "status")}),
        ("Request Data", {"fields": ("headers", "payload"), "classes": ("collapse",)}),
        ("Processing", {"fields": ("processing_result", "error_message")}),
        ("Timestamps", {"fields": ("received_at", "processed_at")}),
    )
