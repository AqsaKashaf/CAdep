import sys
from get_crux import *
from get_ca_details_unit import *
from datetime import datetime
from iso3166 import countries
import dateutil.relativedelta


def check_valid_country(code: str) -> str:
    data = countries.get(code)
    if(data):
        return data.alpha2.lower()
    return None



def main():
    # check if input given
    country = "us"
    if(len(sys.argv) > 1):
        country = sys.argv[1]
        if(not check_valid_country(country)):
            raise Exception("Please enter a valid country code, {country} is not valid")
    
    month = (datetime.now() + dateutil.relativedelta.relativedelta(months=-1)).strftime("%Y%m")
    
    
    websites = extract_crux_file(country, month)
    ocsp_CA = read_OCSP_NAMES()
    for r,w in websites:
        print(find_and_classify(w,ocsp_CA))
        exit()

if __name__ == "__main__":
    main()