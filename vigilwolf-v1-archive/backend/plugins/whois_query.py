import subprocess
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def _validate_domain(domain: str) -> bool:
    """Validate domain name to prevent command injection.

    Only allows letters, digits, hyphens, dots, and unicode domain names.
    Rejects shell metacharacters.
    """
    if not domain or not isinstance(domain, str):
        return False
    # Reject shell metacharacters
    bad_chars = set(';|&$`\\!\n\r<>')
    if any(c in bad_chars for c in domain):
        return False
    # Basic domain regex: allows unicode/IDN domains
    if not re.match(r'^[\w\-.À-ɏḀ-ỿ]+$', domain):
        return False
    return True


def get_whois_info_python_whois(domain):
    """Primary method: Use python-whois library."""
    try:
        import whois
        w = whois.whois(domain)

        def serialize_value(val):
            if isinstance(val, list):
                return [str(v) if v else None for v in val]
            return str(val) if val else None

        result = {
            'domain_name': serialize_value(w.domain_name) if hasattr(w, 'domain_name') else None,
            'registrar': serialize_value(w.registrar) if hasattr(w, 'registrar') else None,
            'creation_date': serialize_value(w.creation_date) if hasattr(w, 'creation_date') else None,
            'expiration_date': serialize_value(w.expiration_date) if hasattr(w, 'expiration_date') else None,
            'updated_date': serialize_value(w.updated_date) if hasattr(w, 'updated_date') else None,
            'name_servers': serialize_value(w.name_servers) if hasattr(w, 'name_servers') else None,
            'status': serialize_value(w.status) if hasattr(w, 'status') else None,
            'emails': serialize_value(w.emails) if hasattr(w, 'emails') else None,
            'country': serialize_value(w.country) if hasattr(w, 'country') else None,
        }
        return result
    except Exception as e:
        raise Exception(f"python-whois failed: {str(e)}")


def get_whois_info_subprocess(domain):
    """Fallback method: Use system whois command with validated input."""
    if not _validate_domain(domain):
        raise Exception("Invalid domain name")

    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise Exception(f"whois command failed with code {result.returncode}")

        whois_text = result.stdout

        parsed = {
            'domain_name': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': None,
            'emails': None,
            'country': None,
            'raw_output': whois_text[:500]
        }

        registrar_match = re.search(r'(?:Registrar|Sponsoring Registrar):\s*(.+)', whois_text, re.IGNORECASE)
        if registrar_match:
            parsed['registrar'] = registrar_match.group(1).strip()

        creation_match = re.search(r'(?:Creation Date|Created|Registration Time):\s*(.+)', whois_text, re.IGNORECASE)
        if creation_match:
            parsed['creation_date'] = creation_match.group(1).strip()

        expiration_match = re.search(r'(?:Expir(?:y|ation) Date|Expires|Registry Expiry Date):\s*(.+)', whois_text, re.IGNORECASE)
        if expiration_match:
            parsed['expiration_date'] = expiration_match.group(1).strip()

        updated_match = re.search(r'(?:Updated Date|Last Updated|Modified):\s*(.+)', whois_text, re.IGNORECASE)
        if updated_match:
            parsed['updated_date'] = updated_match.group(1).strip()

        ns_matches = re.findall(r'(?:Name Server|nserver):\s*(.+)', whois_text, re.IGNORECASE)
        if ns_matches:
            parsed['name_servers'] = [ns.strip().lower() for ns in ns_matches]

        return parsed

    except subprocess.TimeoutExpired:
        raise Exception("whois command timed out")
    except FileNotFoundError:
        raise Exception("whois command not found on system")
    except Exception as e:
        raise Exception(f"subprocess whois failed: {str(e)}")


def get_whois_info(domain):
    """
    Get WHOIS information for a domain with multiple fallback methods.

    Tries in order:
    1. python-whois library
    2. System whois command via subprocess
    3. Returns error with all attempted methods
    """
    if not _validate_domain(domain):
        return {
            'error': 'Invalid domain name',
            'details': ['Domain contains invalid characters'],
            'domain': domain
        }

    errors = []

    try:
        result = get_whois_info_python_whois(domain)
        result['method'] = 'python-whois'
        return result
    except Exception as e:
        errors.append(f"Method 1 (python-whois): {str(e)}")

    try:
        result = get_whois_info_subprocess(domain)
        result['method'] = 'subprocess'
        return result
    except Exception as e:
        errors.append(f"Method 2 (subprocess): {str(e)}")

    return {
        'error': 'All WHOIS lookup methods failed',
        'details': errors,
        'domain': domain
    }
