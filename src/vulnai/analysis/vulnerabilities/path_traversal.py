from vulnai.analysis.vulnerabilities.vulns import VulnerabilityRule

# ============================================================
# CWE-22: Path Traversal
#
# Core idea:
# user-controlled path/filename -> file operation -> no safe path restriction

#os.path.abspath, realpath, normpath, and Path.resolve() are not enough by themselves. They become useful when the code then checks:
#resolved_path is still inside allowed_base_directory
# ============================================================


PATH_TRAVERSAL_SOURCES = [
    # Flask request input
    "request.args",
    "request.args.get",
    "request.form",
    "request.form.get",
    "request.values",
    "request.values.get",
    "request.json",
    "request.get_json",
    "request.files",
    "request.files.get",
    "request.cookies",
    "request.cookies.get",
    "request.headers",
    "request.headers.get",

    # Django request input
    "request.GET",
    "request.GET.get",
    "request.POST",
    "request.POST.get",
    "request.FILES",
    "request.COOKIES",
    "request.COOKIES.get",
    "request.body",
    "request.headers",
    "request.headers.get",

    # FastAPI / Starlette request input
    "Request.query_params",
    "Request.path_params",
    "Request.headers",
    "Request.cookies",
    "Request.json",
    "Request.body",
    "UploadFile.filename",

    # CLI input
    "sys.argv",
    "argparse.ArgumentParser.parse_args",
    "click.argument",
    "click.option",
    "typer.Argument",
    "typer.Option",

    # Environment/config input
    "os.environ",
    "os.environ.get",
    "os.getenv",
    "configparser.ConfigParser.get",

    # Generic input
    "input",

    # Common user-controlled file metadata
    "file.filename",
    "uploaded_file.filename",
    "uploaded_file.name",
]


PATH_TRAVERSAL_SINKS = [
    # Built-in file operations
    "open",

    # pathlib operations
    "Path.open",
    "Path.read_text",
    "Path.read_bytes",
    "Path.write_text",
    "Path.write_bytes",
    "Path.unlink",
    "Path.rename",
    "Path.replace",
    "Path.rmdir",
    "Path.mkdir",

    # os file/path operations
    "os.open",
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.replace",
    "os.rmdir",
    "os.mkdir",
    "os.makedirs",
    "os.listdir",
    "os.scandir",
    "os.walk",
    "os.stat",
    "os.chmod",
    "os.chown",

    # shutil operations
    "shutil.copy",
    "shutil.copyfile",
    "shutil.copytree",
    "shutil.move",
    "shutil.rmtree",

    # Flask file response helpers
    "send_file",
    "flask.send_file",
    "send_from_directory",
    "flask.send_from_directory",

    # Django file response helpers
    "FileResponse",
    "django.http.FileResponse",

    # Archive extraction: can lead to Zip Slip style traversal
    "zipfile.ZipFile.extract",
    "zipfile.ZipFile.extractall",
    "tarfile.TarFile.extract",
    "tarfile.TarFile.extractall",
]


PATH_TRAVERSAL_SANITIZERS = [
    # Filename-only sanitization
    "werkzeug.utils.secure_filename",

    # Flask/Werkzeug safe joining
    "werkzeug.security.safe_join",
    "flask.safe_join",

    # Django safe joining
    "django.utils._os.safe_join",

    # Path normalization / resolution
    # Important: these are only strong if followed by a base-directory check.
    "os.path.abspath",
    "os.path.realpath",
    "os.path.normpath",
    "pathlib.Path.resolve",

    # Base directory checks
    "os.path.commonpath",
    "os.path.commonprefix",

    # Common custom validation helpers
    "validate_path",
    "validate_filename",
    "is_safe_path",
    "is_safe_filename",
    "is_allowed_path",
    "is_allowed_file",
    "is_allowed_extension",
    "allowed_file",
    "safe_path_join",

    # Allowlist-style variables/functions
    "allowed_paths",
    "allowed_files",
    "allowed_extensions",
    "allowlist",
    "whitelist",
]

PATH_TRAVERSAL_RULE = VulnerabilityRule(
    name="Path Traversal",
    cwe="CWE-22",
    detectionType="taintFlow",
    sources=PATH_TRAVERSAL_SOURCES,
    sinks=PATH_TRAVERSAL_SINKS,
    sanitizers=PATH_TRAVERSAL_SANITIZERS,
)