"""Legacy-style view handlers for Analyst1 app.

These view handlers are called by SOAR to render custom views.
"""

import json


def get_ctx_result(result):
    """Extract context from a single result."""
    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["param"] = param

    if data:
        # In SDK apps, data contains IndicatorOutput fields
        # We need to parse raw_data to get the full indicator info
        first_item = data[0] if data else {}
        raw_data = first_item.get("raw_data")
        if raw_data:
            try:
                ctx_result["data"] = json.loads(raw_data)
            except (json.JSONDecodeError, TypeError):
                ctx_result["data"] = first_item
        else:
            ctx_result["data"] = first_item

    if summary:
        ctx_result["summary"] = summary

    return ctx_result


def display_indicators(provides, all_app_runs, context):
    """Legacy-style view handler for indicator lookups.

    This function is called by SOAR when rendering custom views.
    It prepares data for the display_indicators.html template.
    """
    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    context["title_logo"] = "logo_analyst1.svg"

    return "display_indicators.html"
