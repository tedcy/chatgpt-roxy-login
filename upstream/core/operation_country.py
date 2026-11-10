"""Country policy for task execution, independent of persisted account history."""
MAINTENANCE_COUNTRY = "US"


def maintenance_country(value=None):
    country = str(value or "").strip().upper()
    if country and country != MAINTENANCE_COUNTRY:
        raise ValueError("maintenance_proxy_country_invalid")
    return MAINTENANCE_COUNTRY


def registration_country(index=0):
    from core.protocol_country import registration_countries
    from core.proxy_sid import registration_proxy_country_for_index, registration_proxy_country_snapshot
    countries = registration_countries()
    return registration_proxy_country_for_index(countries, index) if countries else ""


def query_country(value):
    country = str(value or "").strip().upper()
    if len(country) != 2 or not country.isascii() or not country.isalpha():
        raise ValueError("query_country_invalid")
    return country


def validate_maintenance_route(route):
    geo = route.get("_validated_geo") or {}
    actual = str(geo.get("country") or geo.get("country_code") or "").strip().upper()
    if actual != MAINTENANCE_COUNTRY:
        raise ValueError("maintenance_proxy_country_unverified" if not actual else "maintenance_proxy_country_drift")
    requested = route.get("plan_region")
    if requested:
        maintenance_country(requested)
    return route
