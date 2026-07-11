from flask import make_response, render_template_string, request
from markupsafe import escape


def cwe_079_local_positive():
    name = request.args.get("name")
    return make_response("<h1>" + name + "</h1>")


def cwe_079_template_positive():
    name = request.form.get("name")
    return render_template_string("<p>%s</p>" % name)


def cwe_079_interprocedural_positive():
    name = request.args.get("name")
    return raw_response(name)


def raw_response(value):
    return make_response(value)


def cwe_079_sanitized_negative():
    name = escape(request.args.get("name"))
    return make_response("<h1>" + name + "</h1>")


def cwe_079_safe_negative():
    return make_response("<h1>hello</h1>")

