from typing import Dict, Any
import google.auth
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession
import googleapiclient.discovery
import json
import os
import base64


def create_service_account(parameters: Dict[str, Any]): # , credentials: Dict[str, Any]
    """Creates a service account."""

    credentials = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"], 
        scopes=['https://www.googleapis.com/auth/cloud-platform'])

    service = googleapiclient.discovery.build(
        'iam', 'v1', credentials=credentials, cache_discovery=False)

    my_service_account = service.projects().serviceAccounts().create(
        name='projects/' + str(parameters["project"]),
        body={
            'accountId': str(parameters["name"]),
            'serviceAccount': {
                'displayName': str(parameters["name"])
            }
        }).execute()

    return my_service_account

def modify_policy_add_member(policy, role, member):
    binding = next(b for b in policy['bindings'] if b['role'] == role)
    binding['members'].append(member)
    print(binding)
    return policy

def create_role_add_member(policy, role, member):
    """Adds a new member to a role binding."""
    binding = {
                'role': role,
                'members': [member]
            }
    print(binding)
    policy['bindings'].append(binding)
    return policy

def generate_policy_bq(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_big_query"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_app_engine(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_app_engine"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_artifact_registry(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_artifact_registry"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_build(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_build"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_functions(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_functions"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_run(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_run"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_scheduler(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_scheduler"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_sql(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_sql"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_storage(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_storage"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_engine(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_engine"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_dataflow(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_dataflow"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_dataproc(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_dataproc"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def generate_policy_pub_sub(parameters: Dict[str, Any],  remove=False): # , credentials: Dict[str, Any]
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"]
        scopes=['https://www.googleapis.com/auth/cloud-platform'])
    service = googleapiclient.discovery.build(
        'cloudresourcemanager', 'v1', credentials=creds, cache_discovery=False)
    project_id = "prj-dataops-test"
    policy=service.projects().getIamPolicy(
                resource=project_id,
                body={},
            ).execute()
    role = parameters["gcp_roles"]["cloud_pub_sub"]
    member="serviceAccount:" + str(parameters["service_account_email1"])
    roles = [b['role'] for b in policy['bindings']]
    if role  in roles:
        new_policy = modify_policy_add_member(policy, role, member)
    elif remove is True:
        new_policy = remove_policy(policy, role, member)
    else:
        new_policy = create_role_add_member(policy, role, member)
    policy = service.projects().setIamPolicy(
            resource=project_id,
            body={
                'policy': new_policy,
    }).execute()
    
    return None

def create_key(parameters: Dict[str, Any]): # , credentials: Dict[str, Any]
    service_account_email1 = str(parameters["service_account_email1"])
    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", #credentials["gcp_file_store_creds"]["token"], 
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    service = googleapiclient.discovery.build("iam", "v1", credentials=creds, cache_discovery=False)
    key = (
        service.projects()
        .serviceAccounts()
        .keys()
        .create(name="projects/-/serviceAccounts/" + service_account_email1, body={})
        .execute()
    )
    info = json.loads(base64.b64decode(key["privateKeyData"]))
    credentials = service_account.Credentials.from_service_account_info(info)
    with open("credentials.json", "w") as f:
        json.dump(info, f, indent=4)
    f.close()

def gcp_create_creds(parameters: Dict[str, Any]): # , credentials: Dict[str, Any]
    
    create_service_account(parameters)
    generate_policy_bq(parameters)
    generate_policy_app_engine(parameters)
    generate_policy_artifact_registry(parameters)
    generate_policy_build(parameters)
    generate_policy_functions(parameters)
    generate_policy_run(parameters)
    generate_policy_scheduler(parameters)
    generate_policy_sql(parameters)
    generate_policy_storage(parameters)
    generate_policy_engine(parameters)
    generate_policy_dataflow(parameters)
    generate_policy_dataproc(parameters)
    generate_policy_pub_sub(parameters)
    create_key(parameters)

    return None