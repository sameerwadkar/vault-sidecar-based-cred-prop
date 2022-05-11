#!/usr/bin/env python

from boto3 import Session
import logging
import os
import json
import flask
from flask import request
import requests as req

app = flask.Flask(__name__)
app.config["DEBUG"] = True


URL_TEMPLATE = "http://127.0.0.1:5010/awscreds?user-name=$user&project-name=$project&refresh=$refresh"
URL_USER_ONLY_TEMPLATE = (
    "http://127.0.0.1:5010/awscreds?user-name=$user&refresh=$refresh"
)
from string import Template

t = Template(URL_TEMPLATE)
tu = Template(URL_USER_ONLY_TEMPLATE)


@app.route("/readmys3folderAsUser", methods=["GET"])
def readmys3folderAsUser():
    user_only = True
    output_as_string = False
    return get_output(request.headers, user_only, output_as_string)


@app.route("/readmys3folderAsProject", methods=["GET"])
def readmys3folderAsProject():
    user_only = False
    output_as_string = False
    return get_output(request.headers, user_only, output_as_string)


def get_output(headers, user_only=False, as_str=True):
    j = get_creds(headers, user_only)
    no_of_creds = j["no_of_creds"]

    bucket = "domino-test-customer-bucket"
    folders = ["test-user-1", "test-user-2", "test-user-3"]
    out_json = {}

    if no_of_creds > 0:
        keys = j["aws_creds"].keys()
        for k in keys:
            session = Session(
                aws_access_key_id=j["aws_creds"][k]["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=j["aws_creds"][k]["AWS_SECRET_ACCESS_KEY"],
                aws_session_token=j["aws_creds"][k]["AWS_SESSION_TOKEN"],
            )
            s3 = session.resource("s3")

            arr = []
            for f in folders:
                mykey = f + "/whoami.txt"
                try:
                    obj = s3.Object(bucket, mykey)
                    txt = obj.get()["Body"].read().decode("utf-8")
                    arr.append({"bucket": bucket, "key": mykey, "value": txt})
                except Exception as err:
                    error_string = str(err)
                    arr.append({"bucket": bucket, "key": mykey, "value": error_string})

            out_json[k] = arr

        s = out_json
        if as_str:
            s = json.dumps(out_json)

    return s


def get_creds(headers, user_only=False):
    user = headers.get("Domino-Username")
    param = headers.get("X-Script-Name")
    refresh = False
    project_name = extract_project(param)
    if "Creds-Refresh" in headers:
        refresh = headers.get("Creds-Refresh")

    if not user_only:

        url = t.substitute(user=user, project=project_name, refresh=refresh)
    else:
        url = tu.substitute(user=user, refresh=refresh)
    print(url)
    response = req.get(url)
    j = response.json()
    j["user"] = user
    j["project_name"] = project_name
    return j


def extract_project(param):
    arr = param.split("/")
    project_name = arr[1].replace(" ", "-") + "-" + arr[2].replace(" ", "-")
    return project_name


customer_s3_bucket = ""
if __name__ == "__main__":
    config_file = "./config/install_config.json"
    if os.path.exists(config_file):
        with open(config_file, "r") as f:
            config = json.load(f)
            customer_s3_bucket = config["customer_s3_bucket"]

    format = "%(asctime)s: %(message)s"
    port_no = 5100
    logging.info("Starting Flask")
    app.run(debug=True, host="0.0.0.0", port=port_no)
    logging.info("Now stopping")
    logging.shutdown()
