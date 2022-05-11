#!/usr/bin/env python
import logging
import sys
from string import Template
import os
import json
import flask
from flask import request
import requests as req

app = flask.Flask(__name__)
app.config["DEBUG"] = True
MAX_TIME_TO_WAIT_FOR_TOKEN_TO_APPEAR = 4
GET_AWS_ROLES_ENDPOINT = "$vault_endpoint/v1/aws/roles/$role"
GET_AWS_CREDS_TOKEN_ENDPOINT = "$vault_endpoint/v1/aws/creds/$role"
GET_AWS_CREDS_ASSUMED_ROLE_ENDPOINT = (
    "$vault_endpoint/v1/aws/creds/$role?role_arn=$role_arn"
)
GET_LEASE_ENDPOINT = "$vault_endpoint/v1/sys/leases/lookup"

creds_cache: dict = {}


def get_vault_headers():
    headers = {"X-Vault-Token": vault_token, "X-Vault-Namespace": vault_namespace}
    return headers


@app.route("/healthz", methods=["GET"])
def healthz():
    return {}


def is_refresh_needed(key):
    if key in creds_cache:
        logging.info("found in cache")
        lease_ids = creds_cache[key]["lease_id"]
        for k, lease_url in lease_ids.items():
            if not is_lease_valid(lease_url):
                return True
        return False
    else:
        return True


def get_creds(key, refresh=False):
    global vault_endpoint
    if not refresh:
        if not is_refresh_needed(key):
            return creds_cache[key]
    else:
        if key in creds_cache:
            creds_cache.pop(key)

    # First get the role description
    t = Template(GET_AWS_ROLES_ENDPOINT)
    url = t.substitute(vault_endpoint=vault_endpoint, role=key)
    print(url)

    response = req.get(url=url, headers=get_headers())
    aws_creds = {}
    lease_id_by_role = {}
    role_type = None
    print(response.status_code)
    if response.status_code == 200:
        j = response.json()
        if response.status_code == 200:
            role_type = j["data"]["credential_type"]
            if role_type == "federation_token" or role_type == "iam_user":
                t = Template(GET_AWS_CREDS_TOKEN_ENDPOINT)
                url = t.substitute(vault_endpoint=vault_endpoint, role=key)
                response = req.put(url=url, headers=get_headers())

                if response.status_code == 200:
                    j = response.json()
                    lease_id = j["lease_id"]
                    env_vars = {
                        "AWS_ACCESS_KEY_ID": j["data"]["access_key"],
                        "AWS_SECRET_ACCESS_KEY": j["data"]["secret_key"],
                        "AWS_SESSION_TOKEN": j["data"]["security_token"],
                    }
                    aws_creds["default"] = env_vars
                    lease_id_by_role["default"] = lease_id
                    out = {
                        "status_code": response.status_code,
                        "aws_creds": aws_creds,
                        "lease_id": lease_id_by_role,
                        "no_of_creds": 1,
                        role_type: role_type,
                    }
                    creds_cache[key] = out
                    return out
                else:
                    return {
                        "status_code": response.status_code,
                        "aws_creds": aws_creds,
                        "lease_id": None,
                        role_type: role_type,
                    }
            elif role_type == "assumed_role":
                role_arns = j["data"]["role_arns"]
                no_of_creds = len(role_arns)
                t = Template(GET_AWS_CREDS_ASSUMED_ROLE_ENDPOINT)

                status_code_by_role = {}
                lease_id_by_role = {}
                for r in role_arns:
                    url = t.substitute(
                        vault_endpoint=vault_endpoint, role=key, role_arn=r
                    )
                    response = req.get(url=url, headers=get_headers())
                    if response.status_code == 200:
                        status_code_by_role[r] = response.status_code
                        j = response.json()
                        lease_id_by_role[r] = j["lease_id"]

                        env_vars = {
                            "AWS_ACCESS_KEY_ID": j["data"]["access_key"],
                            "AWS_SECRET_ACCESS_KEY": j["data"]["secret_key"],
                            "AWS_SESSION_TOKEN": j["data"]["security_token"],
                        }
                        aws_creds[r] = env_vars
                out = {
                    "status_code": status_code_by_role,
                    "aws_creds": aws_creds,
                    "lease_id": lease_id_by_role,
                    "no_of_creds": no_of_creds,
                    role_type: role_type,
                }
                if aws_creds:  # Not Empty
                    creds_cache[key] = out
                return out

    return {
        "status_code": [response.status_code],
        "aws_creds": aws_creds,
        role_type: role_type,
    }


def get_headers():
    global vault_token
    global vault_namespace

    headers = {
        "content-type": "application/json",
        "X-Vault-Token": vault_token,
        "X-Vault-Namespace": vault_namespace,
    }
    return headers


def is_lease_valid(lease_id):
    global vault_endpoint
    t = Template(GET_LEASE_ENDPOINT)
    url = t.substitute(vault_endpoint=vault_endpoint)
    response = req.post(url, headers=get_headers(), json={"lease_id": lease_id})
    if (
        response.status_code == 200 and response.json()["data"]["ttl"] > 60
    ):  # More than a min left for creds to expire
        return True
    else:
        return False


@app.route("/awscreds", methods=["GET"])
def get_aws_credentials():
    args = request.args
    user_name = args.get("user-name")
    refresh = args.get("refresh")
    key = "vault" + "-" + user_name

    if "project-name" in args:
        project_name = args.get("project-name")
        key = "vault-" + project_name + "-" + user_name
    response = get_creds(key, refresh)
    return response


@app.route("/test", methods=["GET"])
def test():
    h = request.headers
    return str(h)


base_path = ""
app_config = {}


port_no = 5003
vault_endpoint = "https://app-dynamic-secrets.vault.7dd8fde3-e358-4555-bfe2-3312a911a4d5.aws.hashicorp.cloud:8200"
vault_namespace = ""
vault_token = ""


def configure_app(base_path):
    global app_config
    global vault_token
    global vault_namespace
    global vault_endpoint

    # print(os.path.join(base_path, 'var/config', 'dynamic-aws-creds-config'))
    # print(os.path.join(base_path, 'var/config', 'dynamic-aws-creds-config'))
    with open(
        os.path.join(base_path, "var/config", "dynamic-aws-creds-config"), "r"
    ) as file:
        data = file.read()
        app_config = json.loads(data)
        print(app_config)
        vault_endpoint = app_config["vault_endpoint"]
        vault_namespace = app_config["vault_namespace"]

    with open(os.path.join(base_path, "var/vault", "token"), "r") as file:
        vault_token = file.read().replace("\n", "")


if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    base_path = sys.argv[1]
    print(base_path)
    port_no = 5010
    if len(sys.argv) > 2:
        port_no = int(sys.argv[2])
    logs_file = os.path.join(base_path, "var/log", "app.log")
    configure_app(base_path)
    logging.basicConfig(
        filename=logs_file,
        filemode="a",
        format="%(asctime)s - %(message)s",
        level=logging.INFO,
        datefmt="%H:%M:%S",
    )
    logging.info("Base path " + base_path)
    logging.info("Starting Flask")
    app.run(debug=True, host="0.0.0.0", port=port_no)
    logging.info("Now stopping")
    logging.shutdown()
