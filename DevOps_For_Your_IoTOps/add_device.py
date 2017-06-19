import requests
import json


def get_token(ip,username,password):
    # print(ip)
    url = "https://%s/api/v1/appmgr/tokenservice" % ip
    print(url)

    r = requests.post(url,auth=(username,password),verify=False)
    token=''
    if  r.status_code == 202:
        print(r.json())
        token = r.json()['token']
        #print(token)
    else:
        print("ERROR")
        print("Status code is "+str(r.status_code))
        print(r.text)
    return(token)


def add_device(ip,token):
    print("add devices")
    ip_range = ["10.10.20.52", "10.10.20.51"]
    print(ip_range)
    for device_ip in ip_range:
        #print("inside for")
        url = "https://%s/api/v1/appmgr/devices" % ip
        headers = {'x-token-id':token,'content-type': 'application/json'}
        print(device_ip)
        data = {'port': '8443', 'ipAddress': device_ip, 'username':'cisco','password':'cisco'}
        r = requests.post(url,data=json.dumps(data),headers=headers,verify=False)
        print(r.status_code)
        if r.status_code < 400:
           print("Device added successfully")
        else:
           r.raise_for_status()


def delete_token(ip, token):
    url = "https://%s/api/v1/appmgr/tokenservice/%s" % (ip, token)
    headers = {'x-token-id':token,'content-type': 'application/json'}
    
    r = requests.delete(url,headers=headers,verify=False)

    if  r.status_code == 200:
        print(r.json())
    else:
        print("ERROR")
        print("Status code is "+str(r.status_code))
        print(r.text)

app_mgr_ip="10.10.20.50"
username="admin"
password="admin_123"
print("loging to FD and fetch an TOKEN")
token_id=get_token(app_mgr_ip,username,password)
print(token_id)
print("Adding the set of devices into FD")
add_device(app_mgr_ip,token_id)
print("Logging out of Fog Director")
