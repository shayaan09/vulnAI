from flask import request
import lxml.etree as LET
import xml.etree.ElementTree as ET
import xml.sax
from xml.dom import minidom


def xxe_001_elementtree_fromstring():
    xml_doc = request.data
    return ET.fromstring(xml_doc)


def xxe_002_elementtree_parse_tainted_path():
    filename = request.args.get("xml")
    return ET.parse(filename)


def xxe_003_minidom_parse_string():
    xml_doc = request.form.get("xml")
    return minidom.parseString(xml_doc)


def xxe_004_sax_parse_string():
    xml_doc = request.get_data()
    return xml.sax.parseString(xml_doc)


def xxe_005_lxml_fromstring():
    xml_doc = request.data
    return LET.fromstring(xml_doc)


def xxe_006_interprocedural_sink_param():
    xml_doc = request.data
    return xxe_006_parse(xml_doc)


def xxe_006_parse(xml_doc):
    return ET.fromstring(xml_doc)


def xxe_007_helper_returns_xml():
    xml_doc = xxe_007_get_xml()
    return ET.fromstring(xml_doc)


def xxe_007_get_xml():
    return request.data


def xxe_008_try_body_sink():
    xml_doc = request.data
    try:
        return ET.fromstring(xml_doc)
    except Exception:
        return None

