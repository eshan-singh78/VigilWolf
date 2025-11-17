import whois

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        result = {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'updated_date': w.updated_date,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails,
            'country': w.country,
        }
        return result
    except Exception as e:
        return {'error': str(e)}
