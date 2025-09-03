from datetime import datetime, timezone

from nomnom.convention import (
    ConventionConfiguration,
    ConventionTheme,
)

theme = ConventionTheme(
    stylesheets="css/lacon-v.css",
    font_urls=[],
)

convention = ConventionConfiguration(
    name="LAcon V",
    subtitle="Convention Subtitle (in lacon_v_app/convention.py)",
    slug="lacon-v",
    site_url="https://www.lacon.org",
    nomination_eligibility_cutoff=datetime(2024, 2, 1, 0, 0, 0, tzinfo=timezone.utc),
    hugo_help_email="hugo-help@lacon.org",
    hugo_admin_email="hugo-admin@lacon.org",
    hugo_packet_backend="digitalocean",
    registration_email="registration@lacon.org",
    logo="images/logo_withouttitle_transparent-300x293.png",
    logo_alt_text="LAcon V logo",
    urls_app_name="lacon_v_app",
    advisory_votes_enabled=True,
)
