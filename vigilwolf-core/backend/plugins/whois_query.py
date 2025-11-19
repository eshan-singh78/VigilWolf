import subprocess
import re
from datetime import datetime

def serialize_value(val):
    """Helper to serialize values for JSON compatibility"""
    if isinstance(val, list):
        return [str(v) if v else None for v in val]
    return str(val) if val else None

def get_whois_info_python_whois(domain):
    """Primary method: Use python-whois library"""
    try:
        import whois
        w = whois.whois(domain)
        
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
    """Fallback method: Use system whois command"""
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
        
        # Parse the raw whois output
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
            'raw_output': whois_text[:500]  # Include first 500 chars of raw output
        }
        
        # Extract registrar
        registrar_match = re.search(r'(?:Registrar|Sponsoring Registrar):\s*(.+)', whois_text, re.IGNORECASE)
        if registrar_match:
            parsed['registrar'] = registrar_match.group(1).strip()
        
        # Extract dates
        creation_match = re.search(r'(?:Creation Date|Created|Registration Time):\s*(.+)', whois_text, re.IGNORECASE)
        if creation_match:
            parsed['creation_date'] = creation_match.group(1).strip()
        
        expiration_match = re.search(r'(?:Expir(?:y|ation) Date|Expires|Registry Expiry Date):\s*(.+)', whois_text, re.IGNORECASE)
        if expiration_match:
            parsed['expiration_date'] = expiration_match.group(1).strip()
        
        updated_match = re.search(r'(?:Updated Date|Last Updated|Modified):\s*(.+)', whois_text, re.IGNORECASE)
        if updated_match:
            parsed['updated_date'] = updated_match.group(1).strip()
        
        # Extract name servers
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
    errors = []
    
    # Method 1: Try python-whois library
    try:
        result = get_whois_info_python_whois(domain)
        result['method'] = 'python-whois'
        return result
    except Exception as e:
        errors.append(f"Method 1 (python-whois): {str(e)}")
    
    # Method 2: Try system whois command
    try:
        result = get_whois_info_subprocess(domain)
        result['method'] = 'subprocess'
        return result
    except Exception as e:
        errors.append(f"Method 2 (subprocess): {str(e)}")
    
    # All methods failed
    return {
        'error': 'All WHOIS lookup methods failed',
        'details': errors,
        'domain': domain
    }
