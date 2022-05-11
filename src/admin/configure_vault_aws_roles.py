import requests
import os
import boto3
import json

if __name__ == "__main__":
    users_file = "./config/users.json"
    config_file = "./config/install_config.json"
    domino_vault_user = ""
    customer_s3_bucket = ""

    aws_client = boto3.client("iam")
    account_id = str(boto3.client("sts").get_caller_identity().get("Account"))

    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            config = json.load(f)
            domino_vault_user = config["domino_vault_user"]
            customer_s3_bucket = config["customer_s3_bucket"]

    users = []
    aws_roles = []
    groups_to_users = {}
    aws_roles_to_policies_mapping = {}
    ad_groups = []
    if os.path.exists(users_file):
        with open(users_file) as f:
            j = json.load(f)
            ad_groups = j["AD_GROUPS"]
            groups_to_users = j["AD_GROUP_TO_USER_MAPPING"]
            group_aws_role_mapping = j["AD_GROUP_TO_AWS_ROLE_MAPPING"]

            aws_roles = j["AWS_ROLES"]
            aws_roles_to_policies_mapping = j["AWS_ROLES_TO_POLICIES_MAPPING"]
            for grp, g_users in groups_to_users.items():
                for u in g_users:
                    if not u in users:
                        users.append(u)

    vault_role_mappings = "./config/vault_role_by_project_and_user.json"
    vault_addr = "http://127.0.0.1:8200"
    vault_ns = ""

    with open("./root/var/vault/token") as f:
        vault_token = f.readline()
    if "VAULT_ADDR" in os.environ:
        vault_addr = os.environ["VAULT_ADDR"]
    if "VAULT_TOKEN" in os.environ:
        vault_token = os.environ["VAULT_TOKEN"]
    if "VAULT_NAMESPACE" in os.environ:
        vault_ns = os.environ["VAULT_NAMESPACE"]

    print(vault_addr)
    print(vault_ns)
    headers = {
        "X-Vault-Token": vault_token,
        "X-Vault-Namespace": vault_ns,
        "Content-Type": "application/json",
    }
    users_by_project_roles = {}
    if os.path.exists(vault_role_mappings):
        with open(vault_role_mappings) as f:
            users_by_project_roles = json.load(f)["users_by_project"]

    owners_and_project = users_by_project_roles.keys()

    for owner_and_project in owners_and_project:
        print(owner_and_project)
        print(users_by_project_roles[owner_and_project])
        collaborators = users_by_project_roles[owner_and_project].keys()

        for c in collaborators:
            policy_arns = []
            user_policies = users_by_project_roles[owner_and_project][c]["policies"]
            for up in user_policies:
                up_arn = f"arn:aws:iam::{account_id}:policy/{up}"
                policy_arns.append(up_arn)
            print(c)
            print(policy_arns)
            put_project_and_user_role_url = f"{vault_addr}/v1/aws/roles/vault-{owner_and_project}-{c}?X-Vault-Token={vault_token}&X-Vault-Namespace={vault_ns}"
            payload = {
                "credential_type": "federation_token",
                "policy_arns": policy_arns,
            }
            response = requests.request(
                "PUT",
                put_project_and_user_role_url,
                headers=headers,
                data=json.dumps(payload),
            )

            get_project_user_creds_url = f"{vault_addr}/v1/aws/creds/vault-{owner_and_project}-{c}?X-Vault-Token={vault_token}&X-Vault-Namespace={vault_ns}"
            print(get_project_user_creds_url)
            # response = requests.request("GET", get_project_user_creds_url, headers=headers)
            # print(response.json())

            print("---")
    roles_by_users = {}
    for g in ad_groups:
        users = groups_to_users[g]
        role = group_aws_role_mapping[g]
        for u in users:
            if u not in roles_by_users:
                roles_by_users[u] = []
            print(f"Role for user {u} is {role} and group is {g}")
            aws_role = f"arn:aws:iam::{account_id}:role/{role}"
            roles_by_users[u].append(aws_role)
    print(roles_by_users)
    for u, v in roles_by_users.items():
        put_user_role_url = f"{vault_addr}/v1/aws/roles/vault-{u}?X-Vault-Token={vault_token}&X-Vault-Namespace={vault_ns}"
        put_user_role_payload = {"credential_type": "assumed_role", "role_arns": v}
        payload = json.dumps(put_user_role_payload)
        response = requests.request(
            "PUT", put_user_role_url, headers=headers, data=payload
        )
        print(response)

        get_user_role_url = f"{vault_addr}/v1/aws/roles/vault-{u}?X-Vault-Token={vault_token}&X-Vault-Namespace={vault_ns}"
        print(get_user_role_url)
        response = requests.request("GET", get_user_role_url, headers=headers)
        j = response.json()
        print(j)
        role_arns = j["data"]["role_arns"]
        print("--------")
        print(role_arns)
        for r in role_arns:
            get_user_creds_url = f"{vault_addr}/v1/aws/creds/vault-{u}?role_arn={r}"
            # response = requests.request("GET", get_user_creds_url, headers=headers)
            print(get_user_creds_url)


