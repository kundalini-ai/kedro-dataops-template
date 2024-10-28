from typing import Dict, Any
import google.auth
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession
import googleapiclient.discovery
import json
import os
import base64

def delete_key(parameters: Dict[str, Any]): # , credentials: Dict[str, Any]
    f = open("credentials.json")
    id = json.load(f)
    key = ("projects/" + str(parameters["project"]) + "/serviceAccounts/" + str(parameters["service_account_email1"]) + "/keys/")
    full_key_name = key + id["private_key_id"]
    print(full_key_name)
    print("Usunięty klucz: " + full_key_name)
    credentials = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"],
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    service = googleapiclient.discovery.build("iam", "v1", credentials=credentials, cache_discovery=False)
    service.projects().serviceAccounts().keys().delete(name=full_key_name).execute()
    f.close()
    os.remove("credentials.json")


def delete_service_account(email): # , credentials: Dict[str, Any]
    """Deletes a service account."""

    creds = service_account.Credentials.from_service_account_file(
        filename= "conf/local/cred-iam.json", # credentials["gcp_file_store_creds"]["token"],
        scopes=['https://www.googleapis.com/auth/cloud-platform'])

    service = googleapiclient.discovery.build(
        'iam', 'v1', credentials=creds, cache_discovery=False)

    service.projects().serviceAccounts().delete(
        name='projects/-/serviceAccounts/' + email).execute()

    print('Deleted service account: ' + email)


def gcp_delete_creds(parameters: Dict[str, Any]): # , credentials: Dict[str, Any]

    delete_key(parameters)
    delete_service_account(parameters["service_account_email1"])
    
    return None