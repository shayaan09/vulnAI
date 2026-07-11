from flask import request
import base64
import marshal
import pickle
import yaml


def deser_001_pickle_loads_request_data():
    payload = request.data
    return pickle.loads(payload)


def deser_002_pickle_load_file_from_tainted_path():
    filename = request.args.get("file")
    return pickle.load(open(filename, "rb"))


def deser_003_yaml_load():
    payload = request.args.get("payload")
    return yaml.load(payload)


def deser_004_marshal_loads():
    payload = request.get_data()
    return marshal.loads(payload)


def deser_005_interprocedural_sink_param():
    payload = request.data
    return deser_005_load(payload)


def deser_005_load(payload):
    return pickle.loads(payload)


def deser_006_helper_returns_payload():
    payload = deser_006_get_payload()
    return pickle.loads(payload)


def deser_006_get_payload():
    return request.data


def deser_007_try_body_sink():
    payload = request.form.get("payload")
    try:
        return pickle.loads(payload)
    except Exception:
        return None


def deser_008_base64_then_pickle():
    encoded = request.args.get("payload")
    payload = base64.b64decode(encoded)
    return pickle.loads(payload)

