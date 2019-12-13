
import json,os,requests,sys
from pprint import pprint

def createDomain(accountId,domain_info,api_auth_token):
    # input = accountId ( distil account ID)
    # domain_info = contains domain initial configuration
    # api auth token 
    # output = create domain on distil portal with default config
    # return = domain ID for further processing
    
    # base url for domain search
    base = 'https://api.distilnetworks.com'

    # set the endpoint you need
    endpoint = '/api/v1/platform/domains'

    # construct the full target url
    target = base + endpoint

    # parameters : ?account_id=xxxx&auth_token=xxxxx 
    parameters = {'account_id' : accountId, 'auth_token' : api_auth_token }
    
    # headers
    headers = {'Content-Type': 'application/json', 'Accept' : 'application/json'}

    # Call REST API
    r = requests.post(target, json=domain_info, headers=headers, params=parameters)

    # Use the json module to load a response into a dictionary.
    r_dict = json.loads(r.text)

    return r_dict['domain']['id']


def updateDomain(accountId,domainId,domain_details,api_auth_token):
    # input = accountId ( distil account ID)
    # domain_ID = newly created domain ID
    # api auth token
    # output = it will update different parameters on the domain

    # base url for domain search
    base = 'https://api.distilnetworks.com'

    # set the endpoint you need
    # Web Security Settings end point 
    endpoint = '/api/v1/platform/web_security_settings'

    # construct the full target url
    target = base + endpoint

    # parameters : ?account_id=xxxx&auth_token=xxxxx 
    parameters = {'account_id' : accountId, 'auth_token' : api_auth_token, 'domain_id': domainId}

    # headers
    headers = {'Content-Type': 'application/json', 'Accept' : 'application/json'}

    r = requests.get(target, params=parameters, headers=headers)

    #print (f'---- \n{r.text}')

    # convert json str to python dictionary 
    resp_data =  json.loads(json.dumps(r.json()))

    # grab a web security id for furhter processing
    web_security_id = resp_data['web_security_settings'][0]['id']

    #print(f"--- \n{r['web_security_settings'][0]['id']}"")
    #print ("--- \n {}".format(resp_data['web_security_settings'][0]['id']))
    print (f"\nWeb Security ID {web_security_id}")

    # Now prepare for RESTful PATCH command

    # set target for web_security as it is same as above target but append the web security id
    # target = target/web_security_id
    target = target + "/" + web_security_id

    # Parameter 
    parameter_web_security = {'auth_token' : api_auth_token}

    response_web_security = requests.patch(target,params=parameter_web_security, json=domain_details)

    print (f'Response status code {response_web_security.status_code}')
    

### Main () 
### Enable following environment Variables 
#  export API_AUTH_TOKEN=xxxx
#  export Account_ID=xxxx
#  export Domain_Name=test.nodomain.com
#  export Origin_Server_IP=192.168.1.100

accountId = os.environ.get('Account_ID')
API_AUTH_TOKEN = os.environ.get('API_AUTH_TOKEN')
domain_info = { "domain": { 
        "name": os.environ.get('Domain_Name'), 
        "origin_server": os.environ.get('Origin_Server_IP') 
        } 
    }

print ("\n --Environment Variables ... ")
print(f"\nAccount_ID : {accountId} \nDomain Name : {domain_info['domain']['name']} \
    \nOrigin Server IP: {domain_info['domain']['origin_server']} \nAPI Auth Token : {API_AUTH_TOKEN}")

print (f"\n --Creating a domain on Distil .... ")

# Distil Cheat sheet ---
# Automated Threats Policy
#   1. Known Violators : known_violators_action
#   2. Identities : bad_user_agent_action
#   3. Aggregator User Agents : aggregator_user_agent_action
#   4. Known Violator Data Centers : service_provider_action
#   5. Automated Browsers : javascript_action
# JavaScript Injection Configuration
#   1. Force Identity : force_identify
# Machine Learning Policy
#   1. Machine Learning Action : machine_learning_action ( Captcha, block, monitor)
#   2. Machine Learning Threshold : machine_learning_threshold ( 1-6 )
# Rate Limiting Policy
#   1. Pages Per minute:
#       Threshold : requests_per_minute
#       Action : requests_per_minute_action
#   2. Pages per Session
#       Threshold : requests_per_session
#       Action : requests_per_session_action
#   3. Session Length
#       Threshold :   session_length   
#       Action : session_length_action


domain_details = {  "web_security_setting": {
         "aggregator_user_agent_action": "block",
        "bad_user_agent_action": "block",
        "known_violators_action": "block",
        "service_provider_action": "block",
        "javascript_action": "block",

        "force_identify": "false",

        "machine_learning_action": "captcha",
        "machine_learning_threshold": 4,

        "requests_per_minute": 20,
        "requests_per_minute_action": "captcha",
        "requests_per_session": 360,
        "requests_per_session_action": "captcha",
        "session_length": 120,
        "session_length_action": "captcha",

    }

}


domain_id = createDomain(accountId,domain_info,API_AUTH_TOKEN)

print (f"Domain created: {domain_info['domain']['name']} \nDomain id: {domain_id}")

print (f"\n --Updating domain configuration ... ")


# Call updateDomain to update its settings 
# 1. First grab a web security ID 
updateDomain(accountId,domain_id,domain_details,API_AUTH_TOKEN)