

import socket
import ssl
import sys
from utils import *

def getcert(addr, timeout=None):
    """Retrieve server's certificate at the specified address (host, port)."""
    # it is similar to ssl.get_server_certificate() but it returns a dict
    # and it verifies ssl unconditionally, assuming create_default_context does
    sock = socket.create_connection(addr, timeout=timeout)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
        # But we instruct the SSL context to *not* validate the hostname.
        
    sslsock = context.wrap_socket(sock, server_hostname=addr[0])
    return sslsock.getpeercert()




def get_CA_details(website: str) -> str :
    
    # get hostname in case if user gave a url as input

    # check if the website format is valid
    host = get_hostname_from_url(website)
    # host = get_domain_from_subdomain(website)

    valid_input = check_if_valid(host)
   
    if(valid_input):
        port = 443
        try:
            cert = getcert((host, port),3)
            cert['website'] = host
        
        except ssl.CertificateError as e:
            print("ssl-certificate-error" + str(e) + "\n")
        
        except socket.error as e:
            print("socket-error" + str(e) + "\n")


def main():
    # check if input given
    if(len(sys.argv) < 2):
        print("\nPlease provide a website name to get its certificate authority details.\n")
        exit(1)

    website = sys.argv[1]

    get_CA_details(website)


if __name__ == "__main__":
    main()