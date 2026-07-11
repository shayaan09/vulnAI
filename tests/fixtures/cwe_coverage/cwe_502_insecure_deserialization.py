from flask import request
import json
import pickle
import yaml


def cwe_502_pickle_positive():
    payload = request.data
    return pickle.loads(payload)


def cwe_502_interprocedural_positive():
    payload = request.get_data()
    return load_payload(payload)


def load_payload(payload):
    return pickle.loads(payload)


def cwe_502_yaml_positive():
    payload = request.args.get("payload")
    return yaml.load(payload)


def cwe_502_try_body_positive():
    payload = request.form.get("payload")
    try:
        return pickle.loads(payload)
    except Exception:
        return None


def cwe_502_safe_negative():
    payload = request.data
    return json.loads(payload)

