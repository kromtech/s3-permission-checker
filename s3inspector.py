import os
import re
import sys

from collections import defaultdict

import boto3
import botocore
import requests
import termcolor

def check_acl(acl):
    dangerous_grants = defaultdict(list)
    for grant in acl.grants:
        grantee = grant['Grantee']
        if grantee['Type'] == 'Group' and grantee['URI'] in groups_to_check:
            dangerous_grants[grantee['URI']].append(grant['Permission'])
    public_indicator = True if dangerous_grants else False
    return public_indicator, dangerous_grants


def get_location(bucket_name):
    loc = s3_client.get_bucket_location(
        Bucket=bucket_name)['LocationConstraint']
    if loc is None:
        loc = 'None(probably North Virginia)'
    return loc


def install_and_import(pkg):
    import importlib
    try:
        importlib.import_module(pkg)
    except ImportError:
        import pip
        pip.main(['install', pkg])
    finally:
        globals()[pkg] = importlib.import_module(pkg)


def scan_bucket_urls(bucket_name):
    domain = 's3.amazonaws.com'
    access_urls = []
    urls_to_scan = [
        'https://{}.{}'.format(bucket_name, domain),
        'http://{}.{}'.format(bucket_name, domain),
        'https://{}/{}'.format(domain, bucket_name),
        'http://{}/{}'.format(domain, bucket_name)
    ]
    for url in urls_to_scan:
        content = requests.get(url).text
        if not re.search('Access Denied', content):
            access_urls.append(url)
    return access_urls


if __name__ == '__main__':
    if sys.version[0] == "3":
        raw_input = input
    packages = ['boto3', 'botocore', 'termcolor', 'requests']
    for package in packages:
        install_and_import(package)
    SEP = '-' * 40
    explained = {
        'READ': 'readable',
        'WRITE': 'writable',
        'READ_ACP': 'permissions readable',
        'WRITE_ACP': 'permissions writeable',
        'FULL_CONTROL': 'Full Control'
    }
    groups_to_check = {
        'http://acs.amazonaws.com/groups/global/AllUsers': 'Everyone',
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers': 'Authenticated AWS users'
    }
    if (os.path.exists('/home/{}/.aws/credentials'.format(os.getlogin())) or
            os.path.exists('/home/{}/.aws/config'.format(os.getlogin()))):
        s3 = boto3.resource('s3')
        s3_client = boto3.client('s3')
    else:
        access_key = raw_input('Enter your AWS access key ID: ')
        secret_key = raw_input('Enter your AWS secret key: ')
        s3 = boto3.resource('s3', aws_access_key_id=access_key,
                            aws_secret_access_key=secret_key)
        s3_client = boto3.client('s3', aws_access_key_id=access_key,
                                 aws_secret_access_key=secret_key)
    bucket_list = []
    buckets = s3.buckets.all()
    try:
        bucketcount = 0
        for bucket in buckets:
            location = get_location(bucket.name)
            print(SEP)
            acl = bucket.Acl()
            public, grants = check_acl(acl)

            if public:
                bucket_line = termcolor.colored(
                    bucket.name, 'blue', attrs=['bold'])
                public_ind = termcolor.colored(
                    'PUBLIC!', 'red', attrs=['bold'])
                termcolor.cprint('Bucket {}: {}'.format(
                    bucket_line, public_ind))
                print('Location: {}'.format(location))
                if grants:
                    for grant in grants:
                        permissions = grants[grant]
                        perm_to_print = [explained[perm]
                                         for perm in permissions]
                        termcolor.cprint('Permission: {} by {}'.format(
                            termcolor.colored(
                                ' & '.join(perm_to_print), 'red'),
                            termcolor.colored(groups_to_check[grant], 'red')))
                urls = scan_bucket_urls(bucket.name)
                print('URLs:')
                if urls:
                    print('\n'.join(urls))
                else:
                    print('Nothing found')
            else:
                bucket_line = termcolor.colored(
                    bucket.name, 'blue', attrs=['bold'])
                public_ind = termcolor.colored(
                    'Not public', 'green', attrs=['bold'])
                termcolor.cprint('Bucket {}: {}'.format(
                    bucket_line, public_ind))
                print('Location: {}'.format(location))
            bucketcount += 1
        if not bucketcount:
            print('No buckets found')
            termcolor.cprint(termcolor.colored('You are safe', 'green'))
    except botocore.exceptions.ClientError as e:
        msg = str(e)
        if 'InvalidAccessKeyId' in msg and 'does not exist' in msg:
            print('The Access Key ID you provided does not exist')
            print('Please, make sure you give me the right credentials')
        elif 'SignatureDoesNotMatch' in msg:
            print('The Secret Access Key you provided is incorrect')
            print('Please, make sure you give me the right credentials')
        elif 'AccessDenied' in msg:
            print('''Access Denied
I need permission to access S3
Check if the IAM user at least has AmazonS3ReadOnlyAccess policy attached

To find the list of policies attached to your user, perform these steps:
1. Go to IAM (https://console.aws.amazon.com/iam/home)
2. Click "Users" on the left hand side menu
3. Click the user, whose credentials you give me
4. Here it is
''')
        else:
            print('''{}
Check your credentials in ~/.aws/credentials file

The user also has to have programmatic access enabled
If you didn't enable it(when you created the account), then:
1. Click the user
2. Go to "Security Credentials" tab
3. Click "Create Access key"
4. Use these credentials'''.format(msg))
