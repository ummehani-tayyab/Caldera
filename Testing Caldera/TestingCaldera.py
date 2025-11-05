#Imports

from datetime import datetime
import pytz
import json
from pprint import pprint
from datetime import datetime
import base64
import time

import requests # requests
import yaml # PyYAML

#------------------------------------------------------------------
#Define the constants from steps 3 and 4

CALDERA_INSTANCE_ADDR = "http://localhost:8888"
CALDERA_REPO_PATH = "C:/******/repo/caldera"
KILL_AFTER = 60

#------------------------------------------------------------------
#Define some helper functions

def load_api_key(caldera_repo_path:str)->str:
    with open(f'{caldera_repo_path}/conf/local.yml', 'r') as r:
        prime_service = yaml.safe_load(r)
    return prime_service['api_key_red']

BASE_URL = f"{CALDERA_INSTANCE_ADDR}/api/v2"
API_KEY = load_api_key(CALDERA_REPO_PATH)
headers = {"KEY":API_KEY, "Accept": "*/*"}
print(API_KEY)

def get_now_utc() -> str:
    return datetime.now(pytz.utc).strftime('%Y-%m-%d %H:%M:%S')

def to_base64(data):
    encoded_data = base64.b64encode(data.encode('utf-8'))
    return encoded_data.decode('utf-8')

def convert_to_encoded_command_psh(powershell_script, verbose=False)->str:
    encoded_powershell_script = to_base64(powershell_script)
    command = f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded_powershell_script}")) | Invoke-Expression'
    if verbose:
        print(f"Encoded PowerShell command:\n{command}")
    return command

def _request(method, url, json=None, headers=headers, params=None, print_url=False):
    if print_url:
        print(url)
    r = requests.request(method, url, json=json, headers=headers, params=params)
    if r.status_code != 200:
        print(r.status_code)
        print(r.text)
        return None
    if method == "head":
        return r.text, r.status_code
    return r.json()

# list agents
def list_agents():
    return _request("get",BASE_URL + "/agents")

def set_agent_sleep_timer(paw: str, sleep_min=1, sleep_max=2):
    return _request("patch", BASE_URL + "/agents/" + paw, json={"sleep_min": sleep_min, "sleep_max": sleep_max})

#------------------------------------------------------------------------------------------------------------------------------------------------
#Set the sleep timers of the agents to a minimum

[set_agent_sleep_timer(agent["paw"]) for agent in list_agents() if list_agents()]

#-------------------------------------------------------------------------------------------------------------------------------------------------
#Define the basic attack function that takes in a command and the plattform

def __begin_attack(command="tree", platform="linux", echo=False, expect_response = True):
    operation_name = f"API OP - {platform}"  # Differentiate operation name by platform
    agents = list_agents()
    if not agents:
        print("No agents available.  Cannot start operation.")
        return None

    selected_agent = None
    executor_name = None
    if platform == "linux":
        for agent in agents:
            if agent["platform"] == "linux" and "sh" in agent["executors"]:
                selected_agent = agent
                executor_name = "sh"
                break
    elif platform == "windows":
        for agent in agents:
            if agent["platform"] == "windows" and "psh" in agent["executors"]:
                selected_agent = agent
                executor_name = "psh"
                break

    if not selected_agent:
        print(f"No suitable agent found for platform: {platform}")
        return None

    operation = _request("post", url=f"{BASE_URL}/operations", json={
        "name": operation_name, "jitter": "1/2", "auto_close": False, "obfuscator": "plain-text", "state": "running",
        "user_learning_parsers": True,
        "adversary": {"adversary_id": "ad-hoc"},
        "group": selected_agent["group"]  # Target the specific agent's group
    })
    if not operation:
        print("Failed to create operation.")
        return None

    operation_id = operation["id"]
    if echo:
        command = f"echo {operation_id};" + command
    payload = {"command": command, "executor": {"name": executor_name, "platform": selected_agent["platform"], "command": command, 
               "code": None, "language": None, "build_target": None, "payloads": [], "uploads": [], "timeout": 60, "parsers": [],
               "variations": [], "additional_info": {}}, "paw": selected_agent["paw"]}
    link = _request("post", f"{BASE_URL}/operations/{operation_id}/potential-links", json=payload)
    if not link:
        print("Failed to create link.")
        return None
    
    if not expect_response: return 0,0
    
    def get_link_response():
        return _request("get",f"{BASE_URL}/operations/{operation_id}/links/{link['id']}/result")
    

    response = get_link_response()
    t0 = time.time()
    while not response or not response.get("result"):
        time.sleep(0.5)
        response = get_link_response()
        if time.time() - t0 > KILL_AFTER:
            raise TimeoutError(f"Command timed out after {KILL_AFTER} seconds.")
    parsed = json.loads(base64.b64decode(response["result"]).decode("utf-8"))
    parsed["stdout"] = parsed["stdout"].replace("\xa0", " ")
    print(parsed["stdout"])
    return operation, parsed["stdout"]

#------------------------------------------------------------------------------------------------------------------------------------------------
#Define the platform and the command to be executed

platform = "windows"
command = "ls"
#-----------------------------------------------------------------------------------------
#Perform the basic attack. The echo=True argument also echoes the operation id on A. This way one can track the processes that were invoked as a cause of this command
operation,_ = __begin_attack(command, platform, echo=True)