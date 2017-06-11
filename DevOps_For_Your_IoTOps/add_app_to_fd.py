import requests
import json
import base64


def get_token(ip,username,password):
    #print(ip)
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
    return token


def delete_token(ip, token):
    url = "https://%s/api/v1/appmgr/tokenservice/%s" % (ip, token)

    headers = {'x-token-id': token, 'content-type': 'application/json'}
    
    r = requests.delete(url,headers=headers,verify=False)

    if  r.status_code == 200:
        print(r.json())
    else:
        print("ERROR")
        print("Status code is "+str(r.status_code))
        print(r.text)


def add_app(ip, token):
    url = "https://%s/api/v1/appmgr/localapps/upload" % ip
    
    headers = {'x-token-id': token}
       
    r = requests.post(url, headers=headers, files={'file': open('NettestApp2V1_lxc.tar.gz','rb')}, verify=False)
                             
    if  r.status_code == 201:
        print(r.json())
    else:
        print("ERROR")
        print("Status code is "+str(r.status_code))
        print(r.text)
        

app_mgr_ip=raw_input("Enter app manager ip address: ")
username=raw_input("Enter the username of your FD: ")
password=raw_input("Enter the password of your FD: ")


# Login to Fog Director
print("Login to Fog Director")
token_id=get_token(app_mgr_ip,username,password)
print(token_id)

print("Adding app 'NettestApp2V1' to Fog Director")
add_app(app_mgr_ip, token_id)

print("Logging out of Fog Director")
delete_token(app_mgr_ip, token_id)

# https://10.10.20.50/api/v1/appmgr/localapps/upload?type=docker&dockerImageName=ciscodevnet%2Fiox-docker-python-web&dockerImageTag=&dockerRegistry=
