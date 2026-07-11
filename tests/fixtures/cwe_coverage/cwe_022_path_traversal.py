from flask import request
from pathlib import Path
from werkzeug.utils import secure_filename
import os


def cwe_022_local_positive():
    filename = request.args.get("file")
    return open(filename).read()


def cwe_022_interprocedural_positive():
    filename = request.args.get("file")
    return read_user_file(filename)


def read_user_file(filename):
    return open(filename).read()


def cwe_022_alias_positive():
    filename = request.form.get("path")
    path_obj = Path(filename)
    return path_obj.read_text()


def cwe_022_try_body_positive():
    filename = request.cookies.get("file")
    try:
        return open(filename).read()
    except OSError:
        return ""


def cwe_022_sanitized_negative():
    filename = secure_filename(request.args.get("file"))
    return open(os.path.join("uploads", filename)).read()


def cwe_022_safe_negative():
    return open("static/report.txt").read()

