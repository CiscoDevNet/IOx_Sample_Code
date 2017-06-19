import requests
import json
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_token(ip, username, password):
    # print(ip)
    url = "https://%s/api/v1/appmgr/tokenservice" % ip
    print(url)

    r = requests.post(url, auth=(username, password), verify=False)
    print(r.request.headers)
    token = ''
    if r.status_code == 202:
        print(r.json())
        token = r.json()['token']
        # print(token)
    else:
        print("ERROR")
        print("Status code is " + str(r.status_code))
        print(r.text)
    return token


def delete_token(ip, token):
    url = "https://%s/api/v1/appmgr/tokenservice/%s" % (ip, token)

    headers = {'x-token-id': token, 'content-type': 'application/json'}

    r = requests.delete(url, headers=headers, verify=False)

    if r.status_code == 200:
        print(r.json())
    else:
        print("ERROR")
        print("Status code is " + str(r.status_code))
        print(r.text)


def is_myapp_present(ip, token, myapp_name):
    url = "https://%s/api/v1/appmgr/myapps?searchByName=%s" % (ip, myapp_name)
    headers = {'x-token-id': token, 'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    print(r.status_code)
    print(r.text)
    if r.text == '{}':
        return False
    else:
        return True


def get_app_details(ip, token, appname):
    url = "https://%s/api/v1/appmgr/localapps?limit=100" % ip
    headers = {'x-token-id': token, 'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    print(r.status_code)

    apps = json.loads((json.dumps(r.json())))

    for index in range(len(apps['data'])):
        if (appname == apps['data'][index]['name']):
            return apps['data'][index]

    return None


def get_myapp_details(ip, token, myapp_name):
    url = "https://%s/api/v1/appmgr/myapps?searchByName=%s" % (ip, myapp_name)
    headers = {'x-token-id': token, 'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    print(r.status_code)
    return json.loads((json.dumps(r.json())))


def get_device_details(ip, token, deviceip):
    url = "https://%s/api/v1/appmgr/devices" % ip
    headers = {'x-token-id': token, 'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    print(r.status_code)

    devices = json.loads((json.dumps(r.json())))

    for index in range(len(devices['data'])):
        if (deviceip == devices['data'][index]['ipAddress']):
            return devices['data'][index]


def uninstall_app(ip, token, appname, deviceip):
    myapp_details = get_myapp_details(ip, token, appname)
    device_details = get_device_details(ip, token, deviceip)

    url = "https://%s/api/v1/appmgr/myapps/%s/action" % (ip, myapp_details['myappId'])
    print("url " + url)
    headers = {'x-token-id': token, 'content-type': 'application/json'}

    data = {"undeploy": {"devices": [0]}}
    data["undeploy"]["devices"][0] = device_details['deviceId']

    print("uninstall data")
    print(json.dumps(data))
    r = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
    print("response")
    print(r.text)


def unpublish_apps(ip, token, app_name):
    url = "https://%s/api/v1/appmgr/localapps?limit=100" % ip
    headers = {'x-token-id': token, 'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    print(r.status_code)

    apps = json.loads((json.dumps(r.json())))

    for index in range(len(apps['data'])):
        appid = apps['data'][index]['localAppId']
        app_name = apps['data'][index]['name']
        appversion = apps['data'][index]['version']
        publish_state = apps['data'][index]['published']
        if publish_state == True and app_name == appname:
            print("UnPublishing App %s" % (app_name))
            apps['data'][index]['published'] = False
            url = "https://%s/api/v1/appmgr/localapps/%s:%s" % (ip, appid, appversion)
            headers = {'x-token-id': token, 'content-type': 'application/json'}
            data = json.dumps(apps['data'][index])
            r = requests.put(url, headers=headers, data=data, verify=False)
            print(r.status_code)


def delete_local_app(ip, token, app_name):
    url = "https://%s/api/v1/appmgr/localapps?limit=100" % ip
    headers = {'x-token-id': token, 'content-type': 'application/json'}
    r = requests.get(url, headers=headers, verify=False)
    print(r.status_code)

    apps = json.loads((json.dumps(r.json())))

    for index in range(len(apps['data'])):
        appid = apps['data'][index]['localAppId']
        print(appid)
        app_name = apps['data'][index]['name']
        appversion = apps['data'][index]['version']
        if app_name == appname:
            print("Deleting App %s from FogDirector!" % (app_name))
            url = "https://%s/api/v1/appmgr/localapps/%s:%s" % (ip, appid, appversion)
            headers = {'x-token-id': token, 'content-type': 'application/json'}
            r = requests.delete(url, headers=headers, verify=False)
            print(r.status_code)


def remove_app(ip, token, appname):
    # https://10.10.20.50/api/v1/appmgr/myapps/4984?cancelOutstandingActions=true
    myapp_details = get_myapp_details(ip, token, appname)

    url = "https://%s/api/v1/appmgr/myapps/%s?cancelOutstandingActions=true" % (ip, myapp_details['myappId'])
    print("url " + url)
    headers = {'x-token-id': token, 'content-type': 'application/json'}

    print("removing app")
    r = requests.delete(url, headers=headers, verify=False)
    print("response")
    print(r.text)


def stop_app(ip, token, appname):
    myapp_details = get_myapp_details(ip, token, appname)

    url = "https://%s/api/v1/appmgr/myapps/%s/action" % (ip, myapp_details['myappId'])
    print("url " + url)
    headers = {'x-token-id': token, 'content-type': 'application/json'}

    data = {"stop": {}}

    print("Stop data")
    print(json.dumps(data))
    r = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
    print("response")
    print(r.text)


def summary_state(ip, token, appname, removeable_statuses):
    status = True
    while status:
        myapp_details = get_myapp_details(ip, token, appname)

        url = "https://%s/api/v1/appmgr/myapps/%s?cancelOutstandingActions=true" % (ip, myapp_details['myappId'])
        print("url " + url)
        headers = {'x-token-id': token, 'content-type': 'application/json'}

        print("removing app")
        r = requests.delete(url, headers=headers, verify=False)
        print("response")
        print(r.text)
        if r.text != removeable_statuses:
            status = False
        else:
            time.sleep(1)


app_mgr_ip = "10.10.20.50"
username = "admin"
password = "admin_123"
appname = "ciscodevnet/go-escaperoom"
deviceip = "10.10.20.52"

removeable_statuses = """{"code":1303,"description":"App ciscodevnet/go-escaperoom is in use: Used By 1 device(s)"}"""

# Login to Fog Director
print("Login to Fog Director")
token_id = get_token(app_mgr_ip, username, password)
print(token_id)

print("Adding app to Fog Director")

# print("Stopping Application %s " % appname)
# stop_app(app_mgr_ip, token_id, appname)

print("Uninstalling Application %s " % appname)
uninstall_app(app_mgr_ip, token_id, appname, deviceip)

# time.sleep(15)
# https://10.10.20.50/api/v1/appmgr/myapps/5284/summaryState

summary_state(app_mgr_ip, token_id, appname, removeable_statuses)

# remove_app(app_mgr_ip, token_id, appname)

unpublish_apps(app_mgr_ip, token_id, appname)

delete_local_app(app_mgr_ip, token_id, appname)

# print("Logging out of Fog Director")
# delete_token(app_mgr_ip, token_id)

