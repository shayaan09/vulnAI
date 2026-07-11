from flask import request
import defusedxml.ElementTree as SafeET
import xml.etree.ElementTree as ET
from xml.dom import minidom


def cwe_611_elementtree_positive():
    xml_doc = request.data
    return ET.fromstring(xml_doc)


def cwe_611_interprocedural_positive():
    xml_doc = request.get_data()
    return parse_user_xml(xml_doc)


def parse_user_xml(xml_doc):
    return ET.fromstring(xml_doc)


def cwe_611_minidom_positive():
    xml_doc = request.form.get("xml")
    return minidom.parseString(xml_doc)


def cwe_611_try_body_positive():
    xml_doc = request.data
    try:
        return ET.fromstring(xml_doc)
    except Exception:
        return None


def cwe_611_safe_negative():
    xml_doc = request.data
    return SafeET.fromstring(xml_doc)

