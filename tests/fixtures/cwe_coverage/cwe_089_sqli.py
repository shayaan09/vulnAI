from flask import request


def cwe_089_local_positive(cursor):
    user_id = request.args.get("id")
    sql = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(sql)


def cwe_089_interprocedural_positive(cursor):
    user_id = request.form.get("id")
    query_user(cursor, user_id)


def query_user(cursor, user_id):
    sql = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(sql)


def cwe_089_suffix_sink_positive(cursor):
    password = input()
    cursor.execute("SELECT * FROM users WHERE password = '" + password + "'")


def cwe_089_parameterized_negative(cursor):
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))


def cwe_089_safe_negative(cursor):
    cursor.execute("SELECT * FROM users")

