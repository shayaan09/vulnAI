from vulnai.analysis.vulns import VulnerabilityRule

# ------------------------------------------------------------
# 1. SOURCES
# Attacker-controlled or user-influenced data.
# These are values that may eventually reach browser-rendered output.
# ------------------------------------------------------------

XSS_FLASK_SOURCES = [
    "input", #not flask, just a general source

    # Query string: /search?q=hello
    "request.args",
    "request.args.get",
    "request.args.__getitem__",

    # Form body: POST form fields
    "request.form",
    "request.form.get",
    "request.form.__getitem__",

    # Combined args + form
    "request.values",
    "request.values.get",
    "request.values.__getitem__",

    # JSON body
    "request.json",
    "request.get_json",

    # Raw request body
    "request.data",
    "request.get_data",

    # Cookies
    "request.cookies",
    "request.cookies.get",
    "request.cookies.__getitem__",

    # Headers
    "request.headers",
    "request.headers.get",
    "request.headers.__getitem__",

    # Uploaded files / filenames
    "request.files",
    "request.files.get",
    "file.filename",
    "FileStorage.filename",
]

XSS_DJANGO_SOURCES = [
    # Query string
    "request.GET",
    "request.GET.get",
    "request.GET.__getitem__",

    # Form body
    "request.POST",
    "request.POST.get",
    "request.POST.__getitem__",

    # Cookies
    "request.COOKIES",
    "request.COOKIES.get",
    "request.COOKIES.__getitem__",

    # Headers / metadata
    "request.headers",
    "request.headers.get",
    "request.META",
    "request.META.get",
    "request.META.__getitem__",

    # Raw body
    "request.body",

    # Uploaded files
    "request.FILES",
    "request.FILES.get",
    "UploadedFile.name",
]

XSS_FASTAPI_STARLETTE_SOURCES = [
    # Starlette/FastAPI Request object
    "request.query_params",
    "request.query_params.get",
    "request.query_params.__getitem__",

    "request.path_params",
    "request.path_params.get",
    "request.path_params.__getitem__",

    "request.headers",
    "request.headers.get",
    "request.headers.__getitem__",

    "request.cookies",
    "request.cookies.get",
    "request.cookies.__getitem__",

    "request.json",
    "request.body",
    "request.form",

    # FastAPI function parameters are often request-controlled.
    # These are pseudo-source categories your analyzer may handle separately.
    "fastapi.query_param",
    "fastapi.path_param",
    "fastapi.body_param",
    "fastapi.form_param",
    "fastapi.cookie_param",
    "fastapi.header_param",
]

XSS_TORNADO_SOURCES = [
    "self.get_argument",
    "self.get_query_argument",
    "self.get_body_argument",
    "self.get_cookie",
    "self.request.arguments",
    "self.request.query_arguments",
    "self.request.body_arguments",
    "self.request.headers",
    "self.request.cookies",
    "self.request.body",
]

XSS_AIOHTTP_SOURCES = [
    "request.query",
    "request.query.get",
    "request.query.__getitem__",

    "request.match_info",
    "request.match_info.get",
    "request.match_info.__getitem__",

    "request.headers",
    "request.headers.get",

    "request.cookies",
    "request.cookies.get",

    "request.json",
    "request.text",
    "request.post",
    "request.read",
]

XSS_BOTTLE_SOURCES = [
    "request.query",
    "request.query.get",

    "request.forms",
    "request.forms.get",

    "request.params",
    "request.params.get",

    "request.cookies",
    "request.cookies.get",

    "request.headers",
    "request.headers.get",

    "request.body",
    "request.json",
]

# Stored-XSS-related pseudo sources.
# These are useful once you want to catch stored XSS.
XSS_STORED_DATA_SOURCES = [
    "database.read",
    "database.fetchone",
    "database.fetchall",
    "cursor.fetchone",
    "cursor.fetchall",
    "cursor.__iter__",

    # ORM-ish pseudo sources
    "Model.query",
    "QuerySet",
    "objects.get",
    "objects.filter",
    "objects.all",

    # User-generated content fields.
    # These are not exact Python calls, but useful semantic categories.
    "db.user_content",
    "db.comment",
    "db.review",
    "db.message",
    "db.profile",
    "db.bio",
    "db.description",
    "db.title",
    "db.name",
]

# Other external/untrusted content sources.
XSS_EXTERNAL_SOURCES = [
    "json.loads",
    "yaml.safe_load",
    "toml.loads",

    # External HTTP data can be attacker-controlled depending on source.
    "requests.get",
    "requests.post",
    "httpx.get",
    "httpx.post",
    "urllib.request.urlopen",

    # Files may contain attacker-controlled HTML/Markdown/log data.
    "open.read",
    "file.read",

    # Markdown/rich text user input
    "markdown.markdown",
    "mistune.html",
]

XSS_ROUTE_PARAM_SOURCES = [
    # Pseudo-source names for framework route params.
    # Example: @app.route("/user/<username>")
    "flask.route_param",
    "django.url_param",
    "fastapi.path_param",
    "starlette.path_param",
    "aiohttp.match_info",
]


XSS_SOURCES = [
    *XSS_FLASK_SOURCES,
    *XSS_DJANGO_SOURCES,
    *XSS_FASTAPI_STARLETTE_SOURCES,
    *XSS_TORNADO_SOURCES,
    *XSS_AIOHTTP_SOURCES,
    *XSS_BOTTLE_SOURCES,
    *XSS_STORED_DATA_SOURCES,
    *XSS_EXTERNAL_SOURCES,
    *XSS_ROUTE_PARAM_SOURCES,
]


# ------------------------------------------------------------
# 2. SINKS
# Places where tainted data can become browser-rendered HTML/JS/CSS.
# ------------------------------------------------------------

XSS_RAW_RESPONSE_SINKS = [
    # Pseudo-sinks for returns your AST analyzer detects manually.
    # Example: return f"<h1>{name}</h1>"
    "raw_html_return",
    "html_string_return",
    "manual_html_construction",
    "return_html",

    # Flask / Werkzeug
    "flask.Response",
    "Response",
    "flask.make_response",
    "make_response",

    # Django
    "django.http.HttpResponse",
    "HttpResponse",
    "django.http.StreamingHttpResponse",
    "StreamingHttpResponse",

    # Starlette / FastAPI
    "starlette.responses.HTMLResponse",
    "HTMLResponse",
    "starlette.responses.Response",
    "fastapi.responses.HTMLResponse",
    "fastapi.responses.Response",

    # Tornado
    "self.write",
    "RequestHandler.write",

    # aiohttp
    "aiohttp.web.Response",
    "web.Response",

    # Bottle
    "template",
    "response.body",
]

XSS_TEMPLATE_STRING_SINKS = [
    # Dangerous because the template itself may be attacker-controlled.
    "flask.render_template_string",
    "render_template_string",

    "jinja2.Template",
    "Template",
    "jinja2.Environment.from_string",
    "Environment.from_string",

    "django.template.Template",
]

XSS_ESCAPE_BYPASS_SINKS = [
    # These usually mean: "trust this as safe HTML."
    # They are NOT sanitizers.
    "markupsafe.Markup",
    "Markup",

    "flask.Markup",

    "django.utils.safestring.mark_safe",
    "mark_safe",
    "SafeString",
    "SafeText",

    # Template-level escape bypasses.
    "template.safe_filter",
    "jinja.safe_filter",
    "django.safe_filter",
    "autoescape_off",
]

XSS_SCRIPT_CONTEXT_SINKS = [
    # Pseudo-sinks for tainted values inserted into <script>.
    "script_context",
    "javascript_string_context",
    "inline_event_handler_context",

    # Examples:
    # <script>const x = "{tainted}"</script>
    # <button onclick="{tainted}">
]

XSS_ATTRIBUTE_CONTEXT_SINKS = [
    # Pseudo-sinks for HTML attributes.
    "html_attribute_context",
    "unquoted_html_attribute_context",

    # Dangerous attributes.
    "href_attribute",
    "src_attribute",
    "action_attribute",
    "formaction_attribute",
    "style_attribute",

    # Event-handler attributes.
    "onclick_attribute",
    "onload_attribute",
    "onerror_attribute",
    "onmouseover_attribute",
]

XSS_DOM_RELATED_SINKS = [
    # These usually appear in JS, not Python,
    # but keeping names helps if vulnAI later scans templates/JS.
    "innerHTML",
    "outerHTML",
    "document.write",
    "insertAdjacentHTML",
    "dangerouslySetInnerHTML",
]

XSS_MARKDOWN_HTML_SINKS = [
    # Markdown converted to HTML and rendered raw can cause XSS
    # if not sanitized after conversion.
    "markdown.markdown",
    "mistune.html",
    "markdown_to_html",
    "rich_text_render",
]


XSS_SINKS = [
    *XSS_RAW_RESPONSE_SINKS,
    *XSS_TEMPLATE_STRING_SINKS,
    *XSS_ESCAPE_BYPASS_SINKS,
    *XSS_SCRIPT_CONTEXT_SINKS,
    *XSS_ATTRIBUTE_CONTEXT_SINKS,
    *XSS_DOM_RELATED_SINKS,
    *XSS_MARKDOWN_HTML_SINKS,
]


# ------------------------------------------------------------
# 3. SANITIZERS
# Things that can make tainted data safer before HTML rendering.
#
# IMPORTANT:
# XSS sanitization is context-specific.
# html.escape is good for HTML text, but not enough for every href,
# JavaScript, CSS, or raw HTML context.
# ------------------------------------------------------------

XSS_HTML_ESCAPE_SANITIZERS = [
    "html.escape",
    "escape",

    "markupsafe.escape",
    "markupsafe.escape_silent",

    "jinja2.escape",

    "django.utils.html.escape",
    "django.utils.html.conditional_escape",
]

XSS_DJANGO_SAFE_HTML_BUILDERS = [
    # These are safer than manual f-strings/concatenation
    # because arguments are escaped before insertion.
    "django.utils.html.format_html",
    "format_html",

    "django.utils.html.format_html_join",
    "format_html_join",
]

XSS_HTML_SANITIZER_LIBRARIES = [
    # For rich text / limited allowed HTML.
    "nh3.clean",

    # Common legacy sanitizer. Still seen in real projects.
    "bleach.clean",
    "bleach.linkify",
]

XSS_TYPE_VALIDATION_SANITIZERS = [
    # These can remove XSS risk by forcing the value into a non-string type.
    "int",
    "float",
    "bool",

    # Pseudo-sanitizers for analyzer-recognized validation patterns.
    "strict_enum_validation",
    "allowlist_validation",
    "literal_choice_validation",
]

XSS_URL_SANITIZERS = [
    # Useful for href/src/action contexts.
    # Escaping alone does not block javascript: URLs.
    "url_has_allowed_host_and_scheme",
    "django.utils.http.url_has_allowed_host_and_scheme",

    # Pseudo-sanitizers for custom URL scheme validation.
    "allowed_url_scheme_validation",
    "http_https_only_validation",
    "relative_url_validation",
]

XSS_JSON_JS_CONTEXT_SANITIZERS = [
    # Safer way to place data into JS contexts is often JSON serialization,
    # not manual string interpolation.
    "json.dumps",

    # Django helper for safely embedding JSON in HTML.
    "django.utils.html.json_script",
    "json_script",

    # Pseudo-sanitizer for framework-provided safe JSON script rendering.
    "safe_json_script_render",
]

XSS_TEMPLATE_AUTOESCAPE_SANITIZERS = [
    # These are not normal Python calls.
    # They are template-level protections.
    "template_autoescape",
    "jinja_autoescape",
    "django_autoescape",
]

XSS_RESPONSE_TYPE_SAFE_SINKS = [
    # These usually produce non-HTML output.
    # I would treat these as safe/low-risk unless later embedded into HTML.
    "flask.jsonify",
    "jsonify",

    "django.http.JsonResponse",
    "JsonResponse",

    "fastapi.responses.JSONResponse",
    "starlette.responses.JSONResponse",
    "JSONResponse",
]


XSS_SANITIZERS = [
    *XSS_HTML_ESCAPE_SANITIZERS,
    *XSS_DJANGO_SAFE_HTML_BUILDERS,
    *XSS_HTML_SANITIZER_LIBRARIES,
    *XSS_TYPE_VALIDATION_SANITIZERS,
    *XSS_URL_SANITIZERS,
    *XSS_JSON_JS_CONTEXT_SANITIZERS,
    *XSS_TEMPLATE_AUTOESCAPE_SANITIZERS,
    *XSS_RESPONSE_TYPE_SAFE_SINKS,
]


# ------------------------------------------------------------
# 4. SAFE RENDERERS
#
# I would keep these separate from sinks.
# render_template(...) is not automatically vulnerable because
# Jinja/Django templates usually autoescape normal variables.
#
# But it can become dangerous if the template uses:
#   {{ value|safe }}
#   {% autoescape false %}
#   unquoted attributes
#   unsafe href/src contexts
# ------------------------------------------------------------

XSS_SAFE_TEMPLATE_RENDERERS = [
    "flask.render_template",
    "render_template",

    "django.shortcuts.render",
    "render",

    "jinja2.Environment.get_template",
    "Template.render",
]

XSS_RULE = VulnerabilityRule(name="Cross-site Scripting",
    cwe="CWE-78",
    detectionType="taintFlow",
    sources=XSS_SOURCES,
    sinks=XSS_SINKS,
    sanitizers=XSS_SANITIZERS,
)

