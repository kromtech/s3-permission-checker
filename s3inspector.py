import os
import re
import sys
import warnings

from datetime import datetime, timedelta
from os.path import expanduser
from collections import defaultdict

# ENTER VALID SNS RESOURCE ARN IF YOU WANT TO USE CODE AS LAMBDA.
SNS_RESOURCE_ARN = "******************************************************"
SEP = "-" * 40

EXPLAINED = {
    "READ": "readable",
    "WRITE": "writable",
    "READ_ACP": "permissions readable",
    "WRITE_ACP": "permissions writeable",
    "FULL_CONTROL": "Full Control"
}

GROUPS_TO_CHECK = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "Everyone",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "Authenticated AWS users"
}

global getInput
getInput = input

def get_s3_obj(is_lambda=False):
    """
    Gets and returns s3 resource and client.

    :param is_lambda: If True - defines that code has been launched as lambda.
    :return: s3 resource and client instances.
    """
    if is_lambda:
        s3 = boto3.resource("s3")
        s3_client = boto3.client("s3")
    else:
        if os.path.exists(os.path.join(expanduser("~"), ".aws", "credentials")) or os.path.exists(
                os.path.join(expanduser("~"), ".aws", "config")):
            profile_name = getInput("Enter your AWS profile name [default]: ") or "default" # modification: raw_input --> getInput
            session = boto3.Session(profile_name=profile_name)
            s3 = session.resource("s3")
            s3_client = session.client("s3")
        else:
            access_key = getInput("Enter your AWS access key ID: ") # modification: raw_input --> getInput
            secret_key = getInput("Enter your AWS secret key: ") # modification: raw_input --> getInput
            s3 = boto3.resource("s3", aws_access_key_id=access_key,
                                aws_secret_access_key=secret_key)
            s3_client = boto3.client("s3", aws_access_key_id=access_key,
                                     aws_secret_access_key=secret_key)
    return s3, s3_client


def tidy(path):
    """
    Removes file described by path.

    :param path: Path to file needs to be removed.
    """
    try:
        os.remove(path)
    except OSError:
        pass


def check_acl(acl):
    """
    Checks if the Access Control List is public.

    :param acl: Acl instance that describes bucket's.
    :return: Bucket's public indicator and dangerous grants parsed from acl instance.
    """
    dangerous_grants = defaultdict(list)
    for grant in acl.grants:
        grantee = grant["Grantee"]
        if grantee["Type"] == "Group" and grantee["URI"] in GROUPS_TO_CHECK:
            dangerous_grants[grantee["URI"]].append(grant["Permission"])
    public_indicator = True if dangerous_grants else False
    return public_indicator, dangerous_grants


def get_location(bucket_name, s3_client):
    """
    Returns the bucket location.

    :param bucket_name: Name of the bucket.
    :param s3_client: s3_client instance.
    :return: String with bucket's region.
    """
    loc = s3_client.get_bucket_location(
            Bucket=bucket_name)["LocationConstraint"]
    if loc is None:
        loc = "None(probably Northern Virginia)"
    return loc


def install_and_import(pkg):
    """
    Installs latest versions of required packages.

    :param pkg: Package name.
    """
    import importlib
    try:
        importlib.import_module(pkg)
    except ImportError:
        import pip
        pip.main(["install", pkg])
    finally:
        globals()[pkg] = importlib.import_module(pkg)


def scan_bucket_urls(bucket_name):
    """
    Scans standard bucket urls.
    Returns only publicly accessible urls.

    :param bucket_name: Name of the bucket.
    :return: List that contains publicly accessible urls.
    """
    domain = "s3.amazonaws.com"
    access_urls = []
    urls_to_scan = [
        "https://{}.{}".format(bucket_name, domain),
        "http://{}.{}".format(bucket_name, domain),
        "https://{}/{}".format(domain, bucket_name),
        "http://{}/{}".format(domain, bucket_name)
    ]
    warnings.filterwarnings("ignore")
    for url in urls_to_scan:
        try:
            content = requests.get(url).text
        except requests.exceptions.SSLError:
            continue
        if not re.search("Access Denied", content):
            access_urls.append(url)
    return access_urls


def add_to_output(msg, path):
    """
    Displays msg or writes it to file.

    :param msg: Message to handle.
    :param path: Path to lambda report file.
    """
    if path is not None:
        with open(path, "a") as f:
            f.write(msg + '\n')
    else:
        termcolor.cprint(msg)


def analyze_buckets(s3, s3_client, report_path=None):
    """
    Analyses buckets permissions. Sends results to defined output.

    :param s3: s3 resource instance.
    :param s3_client: s3 client instance.
    :param report_path: Path to lambda report file.
    """
    buckets = s3.buckets.all()
    try:
        bucketcount = 0

        for bucket in buckets:
            location = get_location(bucket.name, s3_client)
            add_to_output(SEP, report_path)
            bucket_acl = bucket.Acl()
            public, grants = check_acl(bucket_acl)

            if public:
                if report_path:
                    msg = "Bucket {}: {}".format(bucket.name, "PUBLIC!")
                else:
                    bucket_line = termcolor.colored(
                            bucket.name, "blue", attrs=["bold"])
                    public_ind = termcolor.colored(
                            "PUBLIC!", "red", attrs=["bold"])
                    msg = "Bucket {}: {}".format(
                            bucket_line, public_ind)
                add_to_output(msg, report_path)
                add_to_output("Location: {}".format(location), report_path)

                if grants:
                    for grant in grants:
                        permissions = grants[grant]
                        perm_to_print = [EXPLAINED[perm]
                                         for perm in permissions]
                        if report_path:
                            msg = "Permission: {} by {}".format(" & ".join(perm_to_print),
                                                                (GROUPS_TO_CHECK[grant]))
                        else:
                            msg = "Permission: {} by {}".format(
                                    termcolor.colored(
                                            " & ".join(perm_to_print), "red"),
                                    termcolor.colored(GROUPS_TO_CHECK[grant], "red"))
                        add_to_output(msg, report_path)
                urls = scan_bucket_urls(bucket.name)
                add_to_output("URLs:", report_path)
                if urls:
                    add_to_output("\n".join(urls), report_path)
                else:
                    add_to_output("Nothing found", report_path)
            else:
                if report_path:
                    msg = "Bucket {}: {}".format(bucket.name, "Not public")
                else:
                    bucket_line = termcolor.colored(
                            bucket.name, "blue", attrs=["bold"])
                    public_ind = termcolor.colored(
                            "Not public", "green", attrs=["bold"])
                    msg = "Bucket {}: {}".format(
                            bucket_line, public_ind)
                add_to_output(msg, report_path)
                add_to_output("Location: {}".format(location), report_path)
            bucketcount += 1
        if not bucketcount:
            add_to_output("No buckets found", report_path)
            if report_path:
                msg = "You are safe"
            else:
                msg = termcolor.colored("You are safe", "green")
            add_to_output(msg, report_path)
    except botocore.exceptions.ClientError as e:
        resolve_exception(e, report_path)


def lambda_handler(event, context):
    """
    Checks buckets permissions and sends report.
    Will be invoked only by AWS Lambda service.

    :param event: Not used.
    :param context: Not used.
    """
    import boto3
    import botocore
    globals()['boto3'] = boto3
    globals()['botocore'] = botocore
    globals()['requests'] = botocore.vendored.requests

    report_path = "/tmp/report.txt"
    tidy(report_path)
    s3, s3_client = get_s3_obj(is_lambda=True)
    analyze_buckets(s3, s3_client, report_path)
    send_report(report_path)
    tidy(report_path)


def send_report(path):
    """
    Sends report generated by script via sns service.

    :param path: Path to report file.
    """
    sns = boto3.resource("sns")
    platform_endpoint = sns.PlatformEndpoint(SNS_RESOURCE_ARN)
    today = datetime.now() + timedelta(days=1)
    with open(path, "r") as f:
        rts = f.read()
    platform_endpoint.publish(
        Message=rts,
        Subject="S3 Monitor Report: " + str(today),
        MessageStructure="string"
    )


def resolve_exception(exception, report_path):
    """
    Handles exceptions that appears during bucket check run.

    :param exception: Exception instance.
    :param report_path: Path to report path.
    """
    msg = str(exception)
    if report_path:
        if "AccessDenied" in msg:
            add_to_output("""Access Denied
I need permission to access S3
Check if the Lambda Execution Policy at least has AmazonS3ReadOnlyAccess, SNS Publish & Lambda Execution policies attached

To find the list of policies attached to your user, perform these steps:
1. Go to IAM (https://console.aws.amazon.com/iam/home)
2. Click "Roles" on the left hand side menu
3. Click the role lambda is running with 
4. Here it is
""", report_path)
        else:
            add_to_output("""{}
Something has gone very wrong, please check the Cloudwatch Logs Stream for further details""".format(msg),
                          report_path)
    else:
        if "InvalidAccessKeyId" in msg and "does not exist" in msg:
            add_to_output("The Access Key ID you provided does not exist", report_path)
            add_to_output("Please, make sure you give me the right credentials", report_path)
        elif "SignatureDoesNotMatch" in msg:
            add_to_output("The Secret Access Key you provided is incorrect", report_path)
            add_to_output("Please, make sure you give me the right credentials", report_path)
        elif "AccessDenied" in msg:
            add_to_output("""Access Denied
I need permission to access S3
Check if the IAM user at least has AmazonS3ReadOnlyAccess policy attached

To find the list of policies attached to your user, perform these steps:
1. Go to IAM (https://console.aws.amazon.com/iam/home)
2. Click "Users" on the left hand side menu
3. Click the user, whose credentials you give me
4. Here it is
        """, report_path)
        else:
            add_to_output("""{}
Check your credentials in ~/.aws/credentials file

The user also has to have programmatic access enabled
If you didn't enable it(when you created the account), then:
1. Click the user
2. Go to "Security Credentials" tab
3. Click "Create Access key"
4. Use these credentials""".format(msg), report_path)


def main():
    # modification: for Python 2, use raw_input to get user's input 
    if sys.version_info[:2] <= (2, 7):
        getInput = raw_input    
    packages = ["boto3", "botocore", "termcolor", "requests"]
    for package in packages:
        install_and_import(package)
    s3, s3_client = get_s3_obj()
    analyze_buckets(s3, s3_client)


if __name__ == "__main__":
    main()

