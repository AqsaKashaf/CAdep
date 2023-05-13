



website=$1
output=`echo QUIT | timeout 10 openssl s_client -connect $website:443 -status 2> /dev/null | grep -A 17 'OCSP response:' | grep -B 17 'Next Update'`
if [ -z "$var" ]; 
then
    sleep 1;
    output=`echo QUIT | timeout 10 openssl s_client -connect www.$website:443 -status 2> /dev/null | grep -A 17 'OCSP response:' | grep -B 17 'Next Update'`;
fi
echo $website $output 

