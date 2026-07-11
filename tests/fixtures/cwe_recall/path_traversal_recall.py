from flask import request
from pathlib import Path
import codecs
import os


def path_001_open_direct():
    filename = request.args.get("file")
    return open(filename).read()


def path_002_codecs_open():
    filename = request.cookies.get("file")
    return codecs.open(filename, "r", "utf-8").read()


def path_003_pathlib_read_text():
    filename = request.form.get("file")
    return Path(filename).read_text()


def path_004_os_remove():
    filename = request.args.get("file")
    os.remove(filename)


def path_005_interprocedural_sink_param():
    filename = request.args.get("file")
    return path_005_read(filename)


def path_005_read(filename):
    return open(filename).read()


def path_006_helper_returns_path():
    filename = path_006_get_path()
    return open(filename).read()


def path_006_get_path():
    return request.args.get("file")


def path_007_try_body_sink():
    filename = request.args.get("file")
    try:
        return open(filename).read()
    except OSError:
        return ""


def path_008_fstring_path():
    filename = request.args.get("file")
    path = f"/srv/uploads/{filename}"
    return open(path).read()


def path_009_dict_subscript_flow():
    filename = request.args.get("file")
    bag = {"path": filename}
    return open(bag["path"]).read()

