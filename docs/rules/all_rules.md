# vulnAI Vulnerability Overview

This file explains the main vulnerabilities currently supported or planned in vulnAI.

vulnAI’s main goal is not to prove that an attack happened. Its goal is to inspect code and find possible attack paths.

The core idea for most taint-flow vulnerabilities is:

```text
source -> sink without sanitizer = possible vulnerability
```

A **source** is where untrusted data enters the program.  
A **sink** is a dangerous operation.  
A **sanitizer** is a safety check, safe API, validation step, or protection layer.

Some vulnerabilities are taint-flow based. Others are pattern-based.

---

# 1. SQL Injection

## What it is

SQL Injection happens when user-controlled input becomes part of a SQL query.

The developer expects the input to be treated as data, but the database may treat it as SQL syntax.

## Why it is dangerous

An attacker may be able to read, modify, delete, or bypass access controls in the database.

## vulnAI model

```text
user input -> SQL query execution -> no parameterization = possible SQL Injection
```

## Common sources

```text
request.args
request.form
request.json
request.GET
request.POST
input()
sys.argv
```

## Common sinks

```text
cursor.execute()
cursor.executemany()
connection.execute()
session.execute()
raw()
extra()
```

## Common sanitizers / safe patterns

```text
parameterized queries
ORM query builders
prepared statements
bound parameters
```

## Simple vulnerable example

```python
user_id = request.args.get("id")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
```

The user controls part of the SQL query.

## Simple safe example

```python
user_id = request.args.get("id")
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

The user input is passed separately as data, not mixed into the SQL string.

---

# 2. Command Injection

## What it is

Command Injection happens when user-controlled input becomes part of an operating system command.

The developer expects the input to be normal data, like a filename or hostname, but the shell/OS command parser may treat it as command syntax.

## Why it is dangerous

An attacker may be able to run unintended system commands on the server.

## vulnAI model

```text
user input -> os.system/subprocess command -> no protection = possible Command Injection
```

## Common sources

```text
request.args
request.form
request.json
request.GET
request.POST
input()
sys.argv
os.environ
```

## Common sinks

```text
os.system()
os.popen()
subprocess.run()
subprocess.call()
subprocess.Popen()
subprocess.check_output()
subprocess.getoutput()
```

## Common sanitizers / safe patterns

```text
avoid shell=True
use subprocess with argument lists
strict allowlists
safe mapping from user choice to fixed commands
shlex.quote() as a weaker last-resort protection
```

## Simple vulnerable example

```python
host = request.args.get("host")
os.system("ping " + host)
```

The user input becomes part of the command string.

## Simple safe example

```python
host = request.args.get("host")
subprocess.run(["ping", host], shell=False)
```

The command and argument are separated, so the shell does not parse one big command string.

---

# 3. Path Traversal

## What it is

Path Traversal happens when user-controlled input is used to build a file path.

The developer expects a normal filename, but the attacker may try to access files outside the intended folder.

## Why it is dangerous

An attacker may read, write, delete, or expose files they should not access.

## vulnAI model

```text
user input -> file operation -> no safe path restriction = possible Path Traversal
```

## Common sources

```text
request.args
request.form
request.files
request.GET
request.POST
UploadFile.filename
input()
sys.argv
```

## Common sinks

```text
open()
Path.open()
Path.read_text()
Path.read_bytes()
os.remove()
os.unlink()
send_file()
send_from_directory()
zipfile.extractall()
tarfile.extractall()
```

## Common sanitizers / safe patterns

```text
secure_filename()
safe_join()
Path.resolve()
os.path.abspath()
os.path.realpath()
base directory checks
allowed filename/extension checks
```

## Simple vulnerable example

```python
filename = request.args.get("file")
open("uploads/" + filename)
```

The user controls the path used by `open`.

## Simple safe idea

```text
Resolve the final path and verify that it stays inside the intended uploads directory.
```

Path normalization alone is not enough. The app must check that the final resolved path is still inside the allowed folder.

---

# 4. Cross-Site Scripting

## What it is

XSS happens when user-controlled input reaches HTML or JavaScript output without proper escaping.

The browser treats attacker-controlled input as code instead of plain text.

## Why it is dangerous

An attacker may run JavaScript in another user’s browser. This can steal data, perform actions as the user, modify the page, or attack the user’s session.

## vulnAI model

```text
user input -> HTML/JS output -> no escaping = possible XSS
```

## Common sources

```text
request.args
request.form
request.json
request.GET
request.POST
cookies
headers
database values originally created by users
```

## Common sinks

```text
render_template_string()
HttpResponse()
Response()
mark_safe()
Markup()
innerHTML
document.write()
template output with autoescape disabled
```

## Common sanitizers / safe patterns

```text
HTML escaping
template autoescaping
bleach.clean()
safe DOM APIs like textContent
avoid mark_safe on user input
```

## Simple vulnerable example

```python
name = request.args.get("name")
return "<h1>Hello " + name + "</h1>"
```

The user input is inserted directly into HTML.

## Simple safe idea

```text
Escape the user input before placing it into HTML, or use a template engine with autoescaping enabled.
```

---

# 5. Insecure Deserialization

## What it is

Insecure Deserialization happens when the app loads serialized data from an untrusted source using a dangerous deserialization function.

In Python, the classic dangerous example is `pickle`.

## Why it is dangerous

Some deserialization formats can rebuild objects in ways that trigger dangerous behavior. With unsafe formats like pickle, malicious data may lead to code execution.

## vulnAI model

```text
untrusted data -> unsafe deserialization -> possible Insecure Deserialization
```

## Common sources

```text
request.data
request.body
request.files
UploadFile.read()
socket.recv()
open()
Path.read_bytes()
base64.b64decode()
```

## Common sinks

```text
pickle.load()
pickle.loads()
dill.load()
dill.loads()
cloudpickle.loads()
joblib.load()
torch.load()
yaml.load()
marshal.loads()
```

## Common sanitizers / safe patterns

```text
use json.loads() for plain data
use yaml.safe_load()
verify signatures before loading trusted serialized data
avoid pickle for untrusted data
```

## Simple vulnerable example

```python
data = request.data
obj = pickle.loads(data)
```

The app is loading user-controlled data as Python objects.

## Simple safe idea

```text
Use safe data formats like JSON when accepting data from users.
```

---

# 6. Hardcoded Secrets

## What it is

Hardcoded Secrets means passwords, API keys, tokens, private keys, or other secrets are written directly in source code.

## Why it is dangerous

If the code leaks, the secret leaks too. This can expose databases, cloud accounts, APIs, admin tools, or third-party services.

## vulnAI model

```text
secret-looking value in code = possible Hardcoded Secret
```

This is mostly pattern-based, not taint-flow based.

## Common sources

```text
string literals
assignment statements
dictionary values
settings files
config files
```

## Common sinks / patterns

```text
password = "..."
api_key = "..."
secret_key = "..."
access_token = "..."
private_key = "..."
DATABASE_URL = "..."
AWS_SECRET_ACCESS_KEY = "..."
```

## Common sanitizers / safe patterns

```text
os.environ.get()
os.getenv()
secret managers
.env files excluded from source control
deployment config
```

## Simple vulnerable example

```python
API_KEY = "sk_live_abc123"
```

The secret is directly inside the code.

## Simple safe idea

```python
API_KEY = os.environ.get("API_KEY")
```

The code reads the secret from the environment instead of storing it directly.

---

# 7. Weak Cryptography

## What it is

Weak Cryptography happens when the app uses broken, outdated, or risky cryptographic algorithms or uses crypto incorrectly.

Examples include MD5, SHA1, DES, ECB mode, hardcoded encryption keys, and fast hashes for passwords.

## Why it is dangerous

Attackers may crack hashes, recover sensitive data, forge values, or bypass weak protection.

## vulnAI model

```text
sensitive data -> weak crypto API = possible Weak Cryptography
```

This can be pattern-based first, then improved with taint-flow later.

## Common sources

```text
password
token
secret
api_key
session_id
private_key
request.form
request.json
```

## Common sinks

```text
hashlib.md5()
hashlib.sha1()
Crypto.Cipher.DES.new()
Crypto.Cipher.ARC4.new()
AES.MODE_ECB
DES.MODE_ECB
hardcoded crypto keys
```

## Common sanitizers / safe patterns

```text
bcrypt
argon2
scrypt
PBKDF2 with strong parameters
AES-GCM
ChaCha20-Poly1305
Fernet
secrets.token_bytes()
os.urandom()
```

## Simple vulnerable example

```python
hashed = hashlib.md5(password.encode()).hexdigest()
```

MD5 is not safe for password storage.

## Simple safe idea

```text
Use a password hashing algorithm like bcrypt, Argon2, or scrypt.
```

---

# 8. Insecure Random

## What it is

Insecure Random happens when predictable randomness is used for security-sensitive values.

The Python `random` module is fine for games, simulations, and simple random choices, but not for security tokens.

## Why it is dangerous

Attackers may guess or predict reset codes, OTPs, session IDs, API keys, or tokens.

## vulnAI model

```text
random.* -> security-sensitive value = possible Insecure Random
```

This is mostly pattern-based with context.

## Common sources / contexts

```text
token
reset_token
session_id
csrf_token
otp
verification_code
api_key
secret
nonce
salt
```

## Common sinks

```text
random.random()
random.randint()
random.randrange()
random.choice()
random.choices()
random.getrandbits()
random.randbytes()
numpy.random.*
uuid.uuid1()
```

## Common sanitizers / safe patterns

```text
secrets.token_hex()
secrets.token_urlsafe()
secrets.token_bytes()
secrets.choice()
os.urandom()
uuid.uuid4()
```

## Simple vulnerable example

```python
reset_code = random.randint(100000, 999999)
```

The reset code is generated with predictable randomness.

## Simple safe idea

```python
reset_code = secrets.randbelow(900000) + 100000
```

Security-sensitive randomness should come from `secrets` or another cryptographically secure source.

---

# 9. Server-Side Request Forgery

## What it is

SSRF happens when user-controlled input controls a URL that the server requests.

The attacker uses the server as a middleman to access places the attacker may not be able to reach directly.

## Why it is dangerous

The server may be able to access internal services, localhost, private network resources, cloud metadata endpoints, or admin-only systems.

## vulnAI model

```text
user-controlled URL -> server-side HTTP request -> no URL/IP validation = possible SSRF
```

## Common sources

```text
request.args
request.form
request.json
request.GET
request.POST
url
callback_url
webhook_url
target_url
host
domain
```

## Common sinks

```text
requests.get()
requests.post()
requests.request()
httpx.get()
httpx.post()
urllib.request.urlopen()
aiohttp.ClientSession.get()
socket.create_connection()
```

## Common sanitizers / safe patterns

```text
strict domain allowlist
strict scheme allowlist
block localhost
block private IP ranges
validate resolved IP address
reject redirects to unsafe locations
```

## Simple vulnerable example

```python
url = request.args.get("url")
requests.get(url)
```

The user controls where the server sends a request.

## Simple safe idea

```text
Only allow requests to approved domains, and verify the final resolved IP is not private, loopback, or internal.
```

`urlparse()` alone is not enough. It must be followed by real validation.

---

# 10. XML External Entity Injection

## What it is

XXE happens when an app parses untrusted XML using unsafe XML parser settings.

XML can contain external entity references. If the parser follows them, the server may read files or make internal requests.

## Why it is dangerous

XXE can lead to local file disclosure, SSRF, denial of service, or internal network access.

## vulnAI model

```text
untrusted XML -> unsafe XML parser -> possible XXE
```

## Common sources

```text
request.data
request.body
request.files
UploadFile.read()
socket.recv()
open()
Path.read_text()
Path.read_bytes()
```

## Common sinks

```text
xml.etree.ElementTree.parse()
xml.etree.ElementTree.fromstring()
xml.dom.minidom.parse()
xml.dom.minidom.parseString()
xml.sax.parse()
lxml.etree.parse()
lxml.etree.fromstring()
```

## Common sanitizers / safe patterns

```text
defusedxml
disable external entities
disable DTDs
no_network=True
resolve_entities=False
load_dtd=False
safe XML parser configuration
```

## Simple vulnerable example

```python
xml_data = request.data
ET.fromstring(xml_data)
```

The app parses XML directly from user input.

## Simple safe idea

```text
Use defusedxml or configure the XML parser to disable DTDs, external entities, and network access.
```

---

# Rule Type Summary

## Mostly taint-flow based

These usually follow:

```text
source -> sink without sanitizer
```

Examples:

```text
SQL Injection
Command Injection
Path Traversal
XSS
Insecure Deserialization
SSRF
XXE
```

## Mostly pattern-based

These usually look for dangerous code patterns directly:

```text
Hardcoded Secrets
Weak Cryptography
Insecure Random
```

## Final vulnAI mindset

vulnAI does not need to know whether an attacker actually exploited the app.

It only needs to find code that creates a possible attack path:

```text
untrusted input reaches dangerous operation without proper protection
```

That is the core of the project.