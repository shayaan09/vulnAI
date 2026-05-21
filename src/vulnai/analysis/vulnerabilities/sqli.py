from vulnai.analysis.vulns import VulnerabilityRule

# ============================================================
# SQL INJECTION SOURCES
# ============================================================

SQLI_CORE_WEB_SOURCES = [
    # Flask / general request aliases
    "request.args",
    "request.args.get",
    "request.args.getlist",
    "request.form",
    "request.form.get",
    "request.form.getlist",
    "request.values",
    "request.values.get",
    "request.json",
    "request.get_json",
    "request.data",
    "request.get_data",
    "request.files",
    "request.files.get",
    "request.cookies",
    "request.cookies.get",
    "request.headers",
    "request.headers.get",
    "request.view_args",

    # Django
    "request.GET",
    "request.GET.get",
    "request.GET.getlist",
    "request.POST",
    "request.POST.get",
    "request.POST.getlist",
    "request.body",
    "request.COOKIES",
    "request.COOKIES.get",
    "request.headers",
    "request.headers.get",
    "request.META",
    "request.META.get",
    "request.FILES",
    "request.FILES.get",

    # FastAPI / Starlette request object
    "request.query_params",
    "request.path_params",
    "request.headers",
    "request.cookies",
    "request.body",
    "request.json",
    "Request.query_params",
    "Request.path_params",
    "Request.headers",
    "Request.cookies",
    "Request.body",
    "Request.json",

    # FastAPI parameter markers / categories
    "Query",
    "Path",
    "Body",
    "Form",
    "Cookie",
    "Header",
    "UploadFile",
    "fastapi.query_parameter",
    "fastapi.path_parameter",
    "fastapi.body_parameter",
    "fastapi.form_parameter",
    "fastapi.header_parameter",
    "fastapi.cookie_parameter",
    "fastapi.upload_file_parameter",

    # Pydantic request body model fields
    "pydantic.BaseModel.field",
    "pydantic_model_attribute",
    "request_body_model_attribute",
]


SQLI_CLI_AND_SYSTEM_SOURCES = [
    "input",
    "sys.argv",
    "argparse.ArgumentParser.parse_args",
    "argparse.Namespace",
    "click.argument",
    "click.option",
    "typer.Argument",
    "typer.Option",

    # Environment / config can be attacker-controlled in some deployments
    "os.environ",
    "os.getenv",
    "dotenv_values",
    "configparser.ConfigParser.get",
]


SQLI_FILE_AND_DESERIALIZATION_SOURCES = [
    "open",
    "*.read",
    "*.readline",
    "*.readlines",

    "json.load",
    "json.loads",
    "yaml.load",
    "yaml.safe_load",
    "tomllib.load",
    "toml.load",

    "csv.reader",
    "csv.DictReader",

    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",

    "pickle.load",
    "pickle.loads",
    "marshal.load",
    "marshal.loads",
]


SQLI_OTHER_FRAMEWORK_SOURCES = [
    # aiohttp
    "request.query",
    "request.query_string",
    "request.match_info",
    "request.headers",
    "request.cookies",
    "await request.read",
    "await request.text",
    "await request.json",
    "await request.post",
    "await request.multipart",

    # Tornado
    "self.get_argument",
    "self.get_arguments",
    "self.get_query_argument",
    "self.get_query_arguments",
    "self.get_body_argument",
    "self.get_body_arguments",
    "self.request.body",
    "self.request.headers",
    "self.request.cookies",
    "self.path_args",
    "self.path_kwargs",

    # Bottle
    "bottle.request.query",
    "bottle.request.forms",
    "bottle.request.params",
    "bottle.request.json",
    "bottle.request.body",
    "bottle.request.files",
    "bottle.request.cookies",
    "bottle.request.headers",

    # Pyramid
    "request.params",
    "request.GET",
    "request.POST",
    "request.json_body",
    "request.body",
    "request.cookies",
    "request.headers",
    "request.matchdict",

    # Falcon
    "req.params",
    "req.get_param",
    "req.media",
    "req.bounded_stream",
    "req.stream",
    "req.cookies",
    "req.headers",
    "req.get_header",
]


SQLI_NETWORK_AND_EVENT_SOURCES = [
    # WebSocket / socket input
    "websocket.receive",
    "websocket.receive_text",
    "websocket.receive_json",
    "socket.recv",
    "socket.recvfrom",
    "asyncio.StreamReader.read",
    "asyncio.StreamReader.readline",

    # Queue / worker/event payloads
    "celery_task_argument",
    "rq_job_argument",
    "dramatiq_message_argument",
    "kafka_message.value",
    "confluent_kafka.Message.value",
    "rabbitmq_message_body",
    "sqs_message_body",
    "sns_message_body",
    "pubsub_message_data",

    # Serverless
    "aws_lambda_event",
    "aws_lambda_event.queryStringParameters",
    "aws_lambda_event.pathParameters",
    "aws_lambda_event.headers",
    "aws_lambda_event.cookies",
    "aws_lambda_event.body",

    "azure_function_req.params",
    "azure_function_req.get_json",
    "azure_function_req.get_body",
    "azure_function_req.headers",

    "google_cloud_function_request.args",
    "google_cloud_function_request.form",
    "google_cloud_function_request.json",
    "google_cloud_function_request.get_json",
    "google_cloud_function_request.data",
    "google_cloud_function_request.headers",
    "google_cloud_function_request.cookies",
]


SQLI_SECOND_ORDER_SOURCES = [
    # Data read from DB may be user-controlled from an earlier flow
    "cursor.fetchone",
    "cursor.fetchall",
    "cursor.fetchmany",
    "connection.execute().fetchone",
    "connection.execute().fetchall",
    "sqlalchemy_result.fetchone",
    "sqlalchemy_result.fetchall",
    "django_model_field_from_database",
    "orm_model_attribute_from_database",
    "database_record_field",

    # Session/cache-stored user data
    "session",
    "flask.session",
    "request.session",
    "redis.Redis.get",
    "redis.Redis.hget",
    "redis.Redis.hgetall",
    "memcache.Client.get",
    "cache.get",
]


SQLI_EXTERNAL_API_SOURCES = [
    "requests.get().text",
    "requests.get().json",
    "requests.post().text",
    "requests.post().json",
    "httpx.get().text",
    "httpx.get().json",
    "httpx.post().text",
    "httpx.post().json",
    "aiohttp.ClientSession.get().text",
    "aiohttp.ClientSession.get().json",
]

#Create one big list called SQLI_ by taking all the items from these smaller lists and placing them into this one list
SQLI_SOURCES = [
    *SQLI_CORE_WEB_SOURCES,
    *SQLI_CLI_AND_SYSTEM_SOURCES,
    *SQLI_FILE_AND_DESERIALIZATION_SOURCES,
    *SQLI_OTHER_FRAMEWORK_SOURCES,
    *SQLI_NETWORK_AND_EVENT_SOURCES,
    *SQLI_SECOND_ORDER_SOURCES,
    *SQLI_EXTERNAL_API_SOURCES,
]


# ============================================================
# SQL INJECTION SINKS
# ============================================================

SQLI_GENERIC_DBAPI_SINKS = [
    "execute",
    "executemany",
    "executescript",
    "exec_driver_sql",
    "callproc",
    "callfunc",
    "prepare",

    "*.execute",
    "*.executemany",
    "*.executescript",
    "*.exec_driver_sql",
    "*.callproc",
    "*.callfunc",
    "*.prepare",
]


SQLI_SQLITE_SINKS = [
    "sqlite3.Connection.execute",
    "sqlite3.Connection.executemany",
    "sqlite3.Connection.executescript",
    "sqlite3.Cursor.execute",
    "sqlite3.Cursor.executemany",
    "sqlite3.Cursor.executescript",

    "aiosqlite.Connection.execute",
    "aiosqlite.Connection.executemany",
    "aiosqlite.Connection.executescript",
    "aiosqlite.Cursor.execute",
    "aiosqlite.Cursor.executemany",
    "aiosqlite.Cursor.executescript",
]


SQLI_POSTGRES_SINKS = [
    "psycopg.Cursor.execute",
    "psycopg.Cursor.executemany",
    "psycopg.Cursor.copy",
    "psycopg.Cursor.copy_expert",

    "psycopg2.cursor.execute",
    "psycopg2.cursor.executemany",
    "psycopg2.cursor.copy_expert",
    "psycopg2.cursor.copy_from",
    "psycopg2.cursor.copy_to",

    "psycopg3.Cursor.execute",
    "psycopg3.Cursor.executemany",
    "psycopg3.Cursor.copy",

    "asyncpg.Connection.execute",
    "asyncpg.Connection.executemany",
    "asyncpg.Connection.fetch",
    "asyncpg.Connection.fetchrow",
    "asyncpg.Connection.fetchval",
    "asyncpg.Connection.fetchmany",
    "asyncpg.Connection.prepare",
    "asyncpg.Connection.cursor",

    "asyncpg.Pool.execute",
    "asyncpg.Pool.executemany",
    "asyncpg.Pool.fetch",
    "asyncpg.Pool.fetchrow",
    "asyncpg.Pool.fetchval",

    "aiopg.Cursor.execute",
    "aiopg.Cursor.executemany",
]


SQLI_MYSQL_SINKS = [
    "pymysql.cursors.Cursor.execute",
    "pymysql.cursors.Cursor.executemany",
    "pymysql.connections.Connection.query",

    "MySQLdb.cursors.Cursor.execute",
    "MySQLdb.cursors.Cursor.executemany",
    "MySQLdb.connections.Connection.query",

    "mysql.connector.cursor.MySQLCursor.execute",
    "mysql.connector.cursor.MySQLCursor.executemany",
    "mysql.connector.cursor.MySQLCursor.callproc",
    "mysql.connector.connection.MySQLConnection.cmd_query",

    "mariadb.Cursor.execute",
    "mariadb.Cursor.executemany",
    "mariadb.Cursor.callproc",
]


SQLI_ODBC_AND_ORACLE_SINKS = [
    "pyodbc.Cursor.execute",
    "pyodbc.Cursor.executemany",
    "pyodbc.Cursor.prepare",

    "pypyodbc.Cursor.execute",
    "pypyodbc.Cursor.executemany",

    "turbodbc.Cursor.execute",
    "turbodbc.Cursor.executemany",

    "cx_Oracle.Cursor.execute",
    "cx_Oracle.Cursor.executemany",
    "cx_Oracle.Cursor.prepare",
    "cx_Oracle.Cursor.callproc",
    "cx_Oracle.Cursor.callfunc",

    "oracledb.Cursor.execute",
    "oracledb.Cursor.executemany",
    "oracledb.Cursor.prepare",
    "oracledb.Cursor.callproc",
    "oracledb.Cursor.callfunc",
]


SQLI_ORM_AND_FRAMEWORK_SINKS = [
    # SQLAlchemy
    "sqlalchemy.engine.Connection.execute",
    "sqlalchemy.engine.Connection.exec_driver_sql",
    "sqlalchemy.engine.Engine.execute",
    "sqlalchemy.orm.Session.execute",
    "sqlalchemy.orm.Session.scalar",
    "sqlalchemy.orm.Session.scalars",

    "session.execute",
    "db.session.execute",
    "connection.execute",
    "engine.execute",
    "conn.execute",
    "conn.exec_driver_sql",

    # Django raw SQL
    "django.db.connection.cursor.execute",
    "django.db.connection.cursor.executemany",
    "django.db.models.Manager.raw",
    "django.db.models.expressions.RawSQL",

    "cursor.execute",
    "cursor.executemany",
    "connection.cursor().execute",
    "connection.cursor().executemany",
    "Model.objects.raw",
    "objects.raw",
    "RawSQL",

    # Peewee
    "peewee.Database.execute",
    "peewee.Database.execute_sql",
    "peewee.Database.execute_query",
    "peewee.Model.raw",
    "peewee.RawQuery",

    # Pony
    "pony.orm.Database.execute",
    "pony.orm.Database.select",
    "pony.orm.raw_sql",
    "pony.orm.select_by_sql",

    # Tortoise
    "tortoise.connections.Connection.execute_query",
    "tortoise.connections.Connection.execute_query_dict",
    "tortoise.connections.Connection.execute_script",
    "tortoise.models.Model.raw",

    # encode/databases
    "databases.Database.execute",
    "databases.Database.execute_many",
    "databases.Database.fetch_all",
    "databases.Database.fetch_one",
    "databases.Database.fetch_val",
    "databases.Database.iterate",
]


SQLI_DATAFRAME_AND_ANALYTICS_SINKS = [
    # pandas
    "pandas.read_sql",
    "pandas.read_sql_query",
    "pandas.read_sql_table",
    "pd.read_sql",
    "pd.read_sql_query",
    "pd.read_sql_table",

    # Polars
    "polars.read_database",
    "polars.read_database_uri",
    "pl.read_database",
    "pl.read_database_uri",

    # DuckDB
    "duckdb.execute",
    "duckdb.sql",
    "duckdb.query",
    "duckdb.DuckDBPyConnection.execute",
    "duckdb.DuckDBPyConnection.executemany",
    "duckdb.DuckDBPyConnection.sql",
    "duckdb.DuckDBPyConnection.query",

    # Spark / Dask SQL
    "pyspark.sql.SparkSession.sql",
    "SparkSession.sql",
    "spark.sql",
    "dask_sql.Context.sql",
]


SQLI_MIGRATION_SINKS = [
    "alembic.op.execute",
    "op.execute",

    "django.db.migrations.RunSQL",
    "migrations.RunSQL",
]


SQLI_RAW_SQL_CONSTRUCTORS = [
    # These are not always final execution sinks,
    # but they are important pre-sinks / raw SQL creation points.
    "sqlalchemy.text",
    "sqlalchemy.sql.text",
    "sqlalchemy.sql.expression.text",
    "text",

    "django.db.models.expressions.RawSQL",
    "RawSQL",

    "peewee.SQL",
    "peewee.RawQuery",

    "sql.SQL",
    "psycopg.sql.SQL",
    "psycopg2.sql.SQL",

    "literal_column",
    "from_statement",
]

#Create one big list called SQLI_ by taking all the items from these smaller lists and placing them into this one list
SQLI_SINKS = [
    *SQLI_GENERIC_DBAPI_SINKS,
    *SQLI_SQLITE_SINKS,
    *SQLI_POSTGRES_SINKS,
    *SQLI_MYSQL_SINKS,
    *SQLI_ODBC_AND_ORACLE_SINKS,
    *SQLI_ORM_AND_FRAMEWORK_SINKS,
    *SQLI_DATAFRAME_AND_ANALYTICS_SINKS,
    *SQLI_MIGRATION_SINKS,
    *SQLI_RAW_SQL_CONSTRUCTORS,
]


# ============================================================
# SQL INJECTION SANITIZERS
# ============================================================

SQLI_PARAMETERIZATION_SANITIZERS = [
    # General sanitizer concepts
    "parameterized_query",
    "prepared_statement",
    "bound_parameters",
    "bind_variables",
    "placeholder_binding",

    # Generic DB-API safe shape
    "cursor.execute(sql, params)",
    "cursor.executemany(sql, params)",
    "connection.execute(sql, params)",
    "connection.executemany(sql, params)",
    "db.execute(sql, params)",
    "db.executemany(sql, params)",

    # sqlite3 / aiosqlite
    "sqlite3_qmark_placeholder",
    "sqlite3_named_placeholder",
    "sqlite3.Cursor.execute(sql, params)",
    "sqlite3.Cursor.executemany(sql, params)",
    "sqlite3.Connection.execute(sql, params)",
    "sqlite3.Connection.executemany(sql, params)",

    "aiosqlite.Cursor.execute(sql, params)",
    "aiosqlite.Cursor.executemany(sql, params)",
    "aiosqlite.Connection.execute(sql, params)",
    "aiosqlite.Connection.executemany(sql, params)",

    # psycopg / psycopg2 / psycopg3
    "psycopg_percent_s_placeholder",
    "psycopg_named_placeholder",
    "psycopg.Cursor.execute(sql, params)",
    "psycopg.Cursor.executemany(sql, params)",

    "psycopg2.cursor.execute(sql, params)",
    "psycopg2.cursor.executemany(sql, params)",

    "psycopg3.Cursor.execute(sql, params)",
    "psycopg3.Cursor.executemany(sql, params)",

    # asyncpg
    "asyncpg_dollar_placeholder",
    "asyncpg.Connection.execute(sql, params)",
    "asyncpg.Connection.executemany(sql, params)",
    "asyncpg.Connection.fetch(sql, params)",
    "asyncpg.Connection.fetchrow(sql, params)",
    "asyncpg.Connection.fetchval(sql, params)",
    "asyncpg.Pool.execute(sql, params)",
    "asyncpg.Pool.fetch(sql, params)",
    "asyncpg.Pool.fetchrow(sql, params)",
    "asyncpg.Pool.fetchval(sql, params)",

    # MySQL / MariaDB
    "pymysql.cursors.Cursor.execute(sql, params)",
    "pymysql.cursors.Cursor.executemany(sql, params)",

    "MySQLdb.cursors.Cursor.execute(sql, params)",
    "MySQLdb.cursors.Cursor.executemany(sql, params)",

    "mysql.connector.cursor.MySQLCursor.execute(sql, params)",
    "mysql.connector.cursor.MySQLCursor.executemany(sql, params)",

    "mariadb.Cursor.execute(sql, params)",
    "mariadb.Cursor.executemany(sql, params)",

    # ODBC / Oracle
    "pyodbc.Cursor.execute(sql, params)",
    "pyodbc.Cursor.executemany(sql, params)",

    "cx_Oracle.Cursor.execute(sql, params)",
    "cx_Oracle.Cursor.executemany(sql, params)",

    "oracledb.Cursor.execute(sql, params)",
    "oracledb.Cursor.executemany(sql, params)",
]


SQLI_ORM_SANITIZERS = [
    # SQLAlchemy ORM / Core expression API
    "sqlalchemy.select",
    "sqlalchemy.insert",
    "sqlalchemy.update",
    "sqlalchemy.delete",
    "sqlalchemy.where",
    "sqlalchemy.filter",
    "sqlalchemy.filter_by",
    "sqlalchemy.bindparam",
    "sqlalchemy.text_with_bindparams",
    "sqlalchemy.text(sql).bindparams",
    "sqlalchemy.engine.Connection.execute(statement, params)",
    "sqlalchemy.orm.Session.execute(statement, params)",

    "session.execute(statement, params)",
    "db.session.execute(statement, params)",
    "connection.execute(statement, params)",
    "conn.execute(statement, params)",

    # Django ORM normal query APIs
    "Model.objects.filter",
    "Model.objects.get",
    "Model.objects.exclude",
    "Model.objects.create",
    "Model.objects.update",
    "Model.objects.get_or_create",
    "Model.objects.update_or_create",

    "QuerySet.filter",
    "QuerySet.get",
    "QuerySet.exclude",
    "QuerySet.update",

    # Django raw SQL with params
    "django.db.connection.cursor.execute(sql, params)",
    "django.db.connection.cursor.executemany(sql, params)",
    "cursor.execute(sql, params)",
    "cursor.executemany(sql, params)",
    "Model.objects.raw(sql, params)",
    "objects.raw(sql, params)",
    "RawSQL(sql, params)",

    # Peewee / Pony / Tortoise / databases
    "peewee.Model.select",
    "peewee.Model.get",
    "peewee.Model.get_or_none",
    "peewee.Model.update",
    "peewee.Model.insert",
    "peewee.Database.execute_sql(sql, params)",
    "peewee.Model.raw(sql, params)",

    "pony.orm.select",
    "pony.orm.get",
    "pony.orm.exists",
    "pony.orm.Database.execute(sql, params)",

    "tortoise.models.Model.filter",
    "tortoise.models.Model.get",
    "tortoise.models.Model.get_or_none",
    "tortoise.models.Model.create",
    "tortoise.connections.Connection.execute_query(sql, params)",

    "databases.Database.execute(query, values)",
    "databases.Database.execute_many(query, values)",
    "databases.Database.fetch_all(query, values)",
    "databases.Database.fetch_one(query, values)",
    "databases.Database.fetch_val(query, values)",
]


SQLI_IDENTIFIER_AND_FRAGMENT_SANITIZERS = [
    # For table names, column names, ORDER BY, ASC/DESC, operators, etc.
    # These are contextual: only safe if the final SQL fragment comes from trusted constants.
    "allowlist_validation",
    "whitelist_validation",
    "constant_mapping",
    "enum_mapping",
    "literal_mapping",
    "trusted_dictionary_lookup",

    "allowed_columns_dict",
    "allowed_tables_dict",
    "allowed_sort_fields_dict",
    "allowed_sort_directions_dict",
    "allowed_operators_dict",

    "set_membership_check",
    "dict_key_membership_check",
    "match_case_allowlist",
    "typing.Literal",
    "enum.Enum",
    "StrEnum",
    "IntEnum",

    # Psycopg safe identifier composition
    "psycopg.sql.Identifier",
    "psycopg.sql.Literal",
    "psycopg.sql.SQL.format_with_identifier",

    "psycopg2.sql.Identifier",
    "psycopg2.sql.Literal",
    "psycopg2.sql.SQL.format_with_identifier",
]


SQLI_TYPE_VALIDATION_SANITIZERS = [
    # Contextual: good mainly for numeric/typed value positions.
    # Better to downgrade risk than blindly clear taint in every case.
    "int",
    "float",
    "decimal.Decimal",
    "uuid.UUID",
    "ipaddress.ip_address",
    "ipaddress.ip_network",
    "datetime.date.fromisoformat",
    "datetime.datetime.fromisoformat",

    # Pydantic / validation libraries
    "pydantic.conint",
    "pydantic.confloat",
    "pydantic.constr",
    "pydantic.Field(pattern=...)",
    "pydantic.AfterValidator",
    "pydantic.BeforeValidator",

    "marshmallow.fields.Integer",
    "marshmallow.fields.Float",
    "marshmallow.fields.UUID",
    "marshmallow.validate.OneOf",
    "marshmallow.validate.Regexp",

    "wtforms.validators.NumberRange",
    "wtforms.validators.Regexp",
    "wtforms.validators.AnyOf",
    "wtforms.validators.UUID",
]

#Create one big list called SQLI_ by taking all the items from these smaller lists and placing them into this one list
SQLI_SANITIZERS = [
    *SQLI_PARAMETERIZATION_SANITIZERS,
    *SQLI_ORM_SANITIZERS,
    *SQLI_IDENTIFIER_AND_FRAGMENT_SANITIZERS,
    *SQLI_TYPE_VALIDATION_SANITIZERS,
]


#SQLI_RULE = VulnerabilityRule('SQLi', 'CWE-89', 'taintFlow', SQLI_SOURCES, SQLI_SINKS, SQLI_SANITIZERS)