from vulnai.analysis.vulnerabilities.command_injection import COMMAND_RULE
from vulnai.analysis.vulnerabilities.sqli import SQLI_RULE
from vulnai.analysis.vulnerabilities.xss import XSS_RULE
from vulnai.analysis.vulnerabilities.path_traversal import PATH_TRAVERSAL_RULE
from vulnai.analysis.vulnerabilities.insecure_deserialization import INSECURE_DESERIALIZATION_RULE
from vulnai.analysis.vulnerabilities.hardcoded_secrets import HARDCODED_SECRETS_RULE
from vulnai.analysis.vulnerabilities.weak_cryptography import WEAK_CRYPTOGRAPHY_RULE, OWASP_HASH_RULE
from vulnai.analysis.vulnerabilities.insecure_random import INSECURE_RANDOM_RULE, OWASP_WEAK_RANDOM_RULE
from vulnai.analysis.vulnerabilities.ssrf import SSRF_RULE
from vulnai.analysis.vulnerabilities.xxe import XXE_RULE


ALL_RULES = [
    COMMAND_RULE,
    SQLI_RULE,
    XSS_RULE,
    PATH_TRAVERSAL_RULE,
    INSECURE_DESERIALIZATION_RULE,
    HARDCODED_SECRETS_RULE,
    WEAK_CRYPTOGRAPHY_RULE,
    OWASP_HASH_RULE,
    INSECURE_RANDOM_RULE,
    OWASP_WEAK_RANDOM_RULE,
    SSRF_RULE,
    XXE_RULE,
]
