import requests
import json

controller_ip = "127.0.0.1:8080"
base_url = "http://" + controller_ip + "/ms/"
header = {'Content-type': 'application/json', 'Accept': 'text/plain'}

url_users = base_url + "users/json"
url_servers = base_url + "servers/json"
url_switches = base_url + "access-switches/json"

# Users
print(requests.post(url_users, data=json.dumps({"username": "john doe", "mac": "00:00:00:00:00:01"}), headers=header).json())
print(requests.post(url_users, json.dumps({"username": "jane doe", "mac": "00:00:00:00:00:02"}), headers=header).json())
print(requests.post(url_users, json.dumps({"username": "baby doe", "mac": "00:00:00:00:00:03"}), headers=header).json())

# Servers
print(requests.post(url_servers, json.dumps({"ipv4": "10.0.1.1", "mac": "00:00:00:00:01:01"}), headers=header).json())
print(requests.post(url_servers, json.dumps({"ipv4": "10.0.1.2", "mac": "00:00:00:00:01:02"}), headers=header).json())
print(requests.post(url_servers, json.dumps({"ipv4": "10.0.1.3", "mac": "00:00:00:00:01:03"}), headers=header).json())

# Access switches
print(requests.post(url_switches, json.dumps({"dpid": "00:00:00:00:00:00:00:01"}), headers=header).json())
print(requests.post(url_switches, json.dumps({"dpid": "00:00:00:00:00:00:00:03"}), headers=header).json())
print(requests.post(url_switches, json.dumps({"dpid": "00:00:00:00:00:00:00:05"}), headers=header).json())
