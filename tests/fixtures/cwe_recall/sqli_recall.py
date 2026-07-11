from flask import request


def sqli_001_string_concat_execute(cursor):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(sql)


def sqli_002_fstring_execute(cursor):
    name = request.form.get("name")
    sql = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(sql)


def sqli_003_percent_format_execute(cursor):
    password = request.cookies.get("password")
    sql = "SELECT * FROM users WHERE password = '%s'" % password
    cursor.execute(sql)


def sqli_004_dot_format_execute(cursor):
    email = request.headers.get("X-Email")
    sql = "SELECT * FROM users WHERE email = '{}'".format(email)
    cursor.execute(sql)


def sqli_005_join_built_query(cursor):
    user_id = request.args.get("id")
    parts = ["SELECT * FROM users WHERE id = ", user_id]
    sql = "".join(parts)
    cursor.execute(sql)


def sqli_006_helper_returns_query(cursor):
    sql = sqli_006_build_query()
    cursor.execute(sql)


def sqli_006_build_query():
    user_id = request.args.get("id")
    return "SELECT * FROM users WHERE id = " + user_id


def sqli_007_interprocedural_sink_param(cursor):
    user_id = request.form.get("id")
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    sqli_007_execute_query(cursor, sql)


def sqli_007_execute_query(cursor, sql):
    cursor.execute(sql)


def sqli_008_keyword_argument_flow(cursor):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    sqli_008_execute_keyword(cursor=cursor, query=sql)


def sqli_008_execute_keyword(cursor, query):
    cursor.execute(query)


def sqli_009_object_attribute_flow(cursor, holder):
    user_id = request.args.get("id")
    holder.sql = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(holder.sql)


def sqli_010_dict_subscript_flow(cursor):
    user_id = request.args.get("id")
    bag = {}
    bag["sql"] = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(bag["sql"])


def sqli_011_try_body_sink(cursor):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    try:
        cursor.execute(sql)
    except Exception:
        pass


def sqli_012_loop_body_sink(cursor):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    for _ in range(1):
        cursor.execute(sql)

