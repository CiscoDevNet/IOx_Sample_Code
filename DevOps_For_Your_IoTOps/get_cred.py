import requests
import json

# the following import statement removes the in-secure request warning message
# When making a connection to an API URL that has a cert but is not publicly
# or privately signed, and message will pop letting you know about that the
# encrypted connection may not be fully secured since the cert is self signed.
# In a test environment, This is fine.  Please use signed certs in production.

from requests.packages.urllib3.exceptions import InsecureRequestWarning


def get_token(ip, username, password):
    # The url variable defines the url for the API request
    # we will make. The modulo symbol followed by the ip
    # variable will replace the %s with our IP Address
    # defined on line 25.

    url = "https://%s/api/v1/appmgr/tokenservice" % ip
    print(url)

    # By defining our request we are also calling it and saving the
    # contents of that request in the "r" variable

    r = requests.post(url, auth=(username, password), verify=False)
    print(r.request.headers)

    # Here we are defining the "token" variable
    token = ''

    # The next section checks our API request's status code to ensure we have
    # a successful request. Please visit https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
    # if you are not familiar with HTTP status codes.
    if r.status_code == 202:
        print(r.status_code)

        # Now we will save our JSON response in a variable "json_resp".
        # By calling r.json() we will get back the JSON request data
        # in dictionary form.  Dictionaries are the Python language's Hash table.
        # Hash tables make searching through data blazing fast because the information
        # is indexed.  It is like a mini database where we use keys or indexes to quickly
        # find info.
        json_resp = r.json()

        # Next we will save the token variable with the returned data from our
        # request.  By calling the ['token'] key we will get the toke information
        # we need.
        token = json_resp['token']
    else:
        # Since we know what status code to expect, if we get anything else back
        # we will print "ERROR" and the information that was returned.
        print("ERROR")
        print("Status code is ")
        print(r.text)
    return token

app_mgr_ip = "10.10.20.50"
username = "admin"
password = "admin_123"

print(get_token(app_mgr_ip, username, password))

