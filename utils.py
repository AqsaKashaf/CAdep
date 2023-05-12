


import re
import urllib.parse

from tld import get_tld
from tld.utils import update_tld_names

update_tld_names()



def check_if_valid(host: str) -> bool:
    
    if not 1 < len(host) < 253:
        return False

    # Remove trailing dot
    if host[-1] == '.':
        hostname = host[0:-1]

    #  Split hostname into list of DNS labels
    labels = hostname.split('.')

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

    # Check that all labels match that pattern.
    return all(fqdn.match(label) for label in labels)



def get_domain_from_subdomain(domain: str) -> str:
    return get_tld(domain)


def get_hostname_from_url(url: str) -> str:
    
    parsed_url = urllib.parse.urlparse(url)
    return parsed_url.netloc