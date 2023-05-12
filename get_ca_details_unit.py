

import socket
import ssl
import sys
from utils import *
import validators

def getcert(addr, timeout=None):
    """Retrieve server's certificate at the specified address (host, port)."""
    # it is similar to ssl.get_server_certificate() but it returns a dict
    # and it verifies ssl unconditionally, assuming create_default_context does
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=addr[0])
    ssl_sock.connect((addr[0], 443))
    return ssl_sock.getpeercert()

def parse_cert(cert: str, getSAN: bool) -> dict: 
    result = {}

    if("OCSP" in cert):
        ocsp = cert["OCSP"][0]  
        ocsp_domain = urllib.parse.urlparse(ocsp).netloc
        if(ocsp_domain):
            result["ocsp"] = ocsp_domain
   
    if("crlDistributionPoints" in cert):
        crl = cert["crlDistributionPoints"][0]
        crl_domain = urllib.parse.urlparse(crl).netloc
        if(crl_domain):
            result["crl"] = crl_domain
    if(getSAN):
        san_list = cert["subjectAltName"]
        result["san"] = set()
        for san in san_list:
            san_domain = san[1] #get_domain_from_subdomain(san[1])
            result["san"].add(san_domain)

    return result



def get_CA_details(host: str, getSAN: bool) -> str :
    
   
   
    if(validators.url(host)):
        host = get_hostname_from_url(host)
    
    valid_input = check_if_valid(host)
   
    if(valid_input):
        port = 443
        try:
            cert = getcert((host, port),3)
            # print(cert)
            details = parse_cert(cert, getSAN)
            return details
        except ssl.CertificateError as e:
            return ("ssl-certificate-error" + str(e) + "\n")
        
        except socket.error as e:
            return("socket-error" + str(e) + "\n")

    else:
        raise Exception("Invalid input")


def main():
    # check if input given
    if(len(sys.argv) < 2):
        raise Exception("\nPlease provide a website name to get its certificate authority details.\n")
        exit(1)
    
    get_SAN = False

    if(len(sys.argv) > 2):
        if(sys.argv[2] == "--get-san"):
            get_SAN = True
            if(len(sys.argv) == 4):
                SAN_LIB = sys.argv[3]
            else:
                raise Exception("\nPlease provide a path to the SAN file\n")
    
    host = sys.argv[1]
   
    details = get_CA_details(host, get_SAN)
    


if __name__ == "__main__":
    main()