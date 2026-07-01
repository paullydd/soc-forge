from soc_forge.ui.colors import Colors
from soc_forge.ui.panels import header, status_card, activity_feed


def show_dashboard(get_dashboard_stats, get_recent_activity, box_row, color_status, color_severity):
    header("SOC-FORGE COMMAND CENTER")

    stats = get_dashboard_stats()
    recent = get_recent_activity()

    status_card(
        "DASHBOARD",
        [
            ("System", Colors.GREEN + "ONLINE" + Colors.RESET),
            ("Alerts", stats["alerts"]),
            ("Cases", stats["cases"]),
            ("Open Cases", stats["open"]),
            ("Investigating", stats["investigating"]),
            ("High Severity", stats["high"]),
            ("Medium Severity", stats["medium"]),
            ("Low Severity", stats["low"]),
        ],
    )

    activity_feed(
        "RECENT SOC ACTIVITY",
        [
            {
                "timestamp": item["timestamp"],
                "title": item["title"],
                "severity": color_severity(item["severity"]),
            }
            for item in recent
        ],
        limit=3,
    )