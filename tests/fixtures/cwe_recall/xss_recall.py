from flask import make_response, render_template_string, request
from markupsafe import Markup


def xss_001_make_response_concat():
    name = request.args.get("name")
    return make_response("<h1>" + name + "</h1>")


def xss_002_render_template_string_fstring():
    name = request.form.get("name")
    return render_template_string(f"<p>{name}</p>")


def xss_003_markup_escape_bypass():
    html = request.args.get("html")
    return Markup(html)


def xss_004_interprocedural_raw_response():
    html = request.args.get("html")
    return xss_004_send_raw(html)


def xss_004_send_raw(html):
    return make_response(html)


def xss_005_helper_returns_html():
    html = xss_005_build_html()
    return make_response(html)


def xss_005_build_html():
    name = request.args.get("name")
    return "<h1>" + name + "</h1>"


def xss_006_header_source():
    agent = request.headers.get("User-Agent")
    return make_response(agent)


def xss_007_try_body_sink():
    html = request.args.get("html")
    try:
        return make_response(html)
    except Exception:
        return make_response("")


def xss_008_object_attribute_flow(holder):
    html = request.args.get("html")
    holder.html = html
    return make_response(holder.html)

