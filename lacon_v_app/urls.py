app_name = "lacon_v_app"
from django.urls import path  # noqa: E402

from . import views  # noqa: E402

urlpatterns = [path("regfox_webhook/", views.regfox_webhook, name="regfox_webhook")]
