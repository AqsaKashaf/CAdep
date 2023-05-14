import sys
from get_crux import *
from get_ca_details_unit import *





def main():
    # check if input given
    country = "us"
    if(len(sys.argv) > 1):
        country = sys.argv[1]
        if(not check_valid_country(country)):
            raise Exception("Please enter a valid country code, {country} is not valid")
    
    month = get_last_month()
    
    
    websites = extract_crux_file(country, month)
    ocsp_CA = read_OCSP_NAMES()
    results = {}
    count = 0
    for r,w in websites:
        output = find_and_classify(w,ocsp_CA)
        results[(r,w)] = output
        count+=1
        if(count == 5):
            print(country,"ca",month,results)
            write_results(country,"ca",month,results)
            results = {}
            count = 0
            exit()


        

if __name__ == "__main__":
    main()