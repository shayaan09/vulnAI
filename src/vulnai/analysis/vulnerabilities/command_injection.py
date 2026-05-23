from vulnai.analysis.vulns import VulnerabilityRule

# ============================================================
# CWE-78: OS Command Injection
# Core idea:
# untrusted input -> OS command execution -> no strong sanitizer
# ============================================================


# ----------------------------
# Sources: external/user input
# ----------------------------

COMMAND_INJECTION_SOURCES = [
    # Flask request input
    "request.args",
    "request.args.get",
    "request.form",
    "request.form.get",
    "request.values",
    "request.values.get",
    "request.json",
    "request.get_json",
    "request.data",
    "request.files",
    "request.cookies",
    "request.cookies.get",
    "request.headers",
    "request.headers.get",

    # Django request input
    "request.GET",
    "request.GET.get",
    "request.POST",
    "request.POST.get",
    "request.body",
    "request.FILES",
    "request.COOKIES",
    "request.COOKIES.get",
    "request.headers",
    "request.headers.get",
    "request.META",
    "request.META.get",

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

    # Environment input
    "os.environ",
    "os.environ.get",
    "os.getenv",

    # File/config input: lower confidence, but still external
    "open",
    "Path.read_text",
    "Path.read_bytes",
    "json.load",
    "json.loads",
    "yaml.safe_load",
    "toml.load",
    "configparser.ConfigParser.get",

    # Generic input
    "input",
]


# ----------------------------
# Sinks: OS command execution
# ----------------------------

COMMAND_INJECTION_SINKS = [
    # Direct shell command execution
    "os.system",
    "os.popen",

    # subprocess module
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",

    # os exec family
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",

    # os spawn family
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",

    # pty/process related
    "pty.spawn",

    # Older/deprecated command execution style
    "commands.getoutput",
    "commands.getstatusoutput",

    # Common wrapper names in projects
    "run_command",
    "execute_command",
    "exec_command",
    "shell",
    "run_shell",
    "execute_shell",
    "system",
    "cmd",
]


# ----------------------------
# Sanitizers / safe guards
# ----------------------------

COMMAND_INJECTION_SANITIZERS = [
    # Strong validation helpers
    "validate_command_input",
    "validate_shell_arg",
    "validate_filename",
    "validate_path",
    "validate_hostname",
    "validate_ip",
    "validate_domain",
    "is_safe_command_arg",
    "is_allowed_command",
    "is_allowed_host",
    "is_allowed_path",
    "is_safe_path",

    # Allowlist style checks
    "allowlist",
    "whitelist",
    "allowed_commands",
    "allowed_args",
    "allowed_hosts",
    "allowed_paths",
    "allowed_values",

    # Regex validation
    "re.fullmatch",
    "re.match",

    # Parsing/validation libraries
    "ipaddress.ip_address",
    "ipaddress.ip_network",
    "urllib.parse.urlparse",

    # Shell escaping: useful, but weaker than avoiding shell=True
    "shlex.quote",

    # Safer path handling, useful for path-like command arguments
    "os.path.abspath",
    "os.path.realpath",
    "pathlib.Path.resolve",
]


# ----------------------------
# Safe patterns that are NOT simple function sanitizers
# Analyzer should treat these separately later.
# ----------------------------

COMMAND_INJECTION_SAFE_PATTERNS = [
    # subprocess with argument list and no shell
    "subprocess_list_args_shell_false",

    # fixed executable name, user input only as separated argument
    "fixed_command_with_separated_args",

    # user input maps to a fixed command from an allowlist/dictionary
    "tainted_choice_to_fixed_command_mapping",

    # Python library API used instead of shell command
    "safe_library_replacement",

    # explicit shell=False
    "shell_false",
]


# ----------------------------
# Dangerous patterns / risk boosters
# These should increase confidence/severity.
# ----------------------------

COMMAND_INJECTION_DANGEROUS_PATTERNS = [
    "shell_true",
    "string_concatenation_command",
    "f_string_command",
    "format_string_command",
    "percent_format_command",
    "join_built_command",
    "tainted_executable_position",
    "tainted_command_string",
]

COMMAND_RULE = VulnerabilityRule(
    name="Command Injection",
    cwe="CWE-78",
    detectionType="taintFlow",
    sources=COMMAND_INJECTION_SOURCES,
    sinks=COMMAND_INJECTION_SINKS,
    sanitizers=COMMAND_INJECTION_SANITIZERS,
)

