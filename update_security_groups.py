'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

Modified by Jason Klein, Logic Forte

Learn more about published AWS IP ranges here
https://aws.amazon.com/blogs/aws/aws-ip-ranges-json/
https://aws.amazon.com/blogs/security/how-to-automatically-update-your-security-groups-for-amazon-cloudfront-and-aws-waf-by-using-aws-lambda/

This function should be automatically invoked via an SNS notification broadcast by AWS each time AWS updates their IP ranges.
https://aws.amazon.com/blogs/aws/subscribe-to-aws-public-ip-address-changes-via-amazon-sns/
arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged

Trying to manually invoke this function? Download the JSON file, calculate the MD5, update the MD5 in TestInvokeViaSNS, then run TestInvokeViaSNS.
'''

import boto3
import hashlib
import json
import urllib2

from netaddr import IPNetwork, cidr_merge

# Name of the region, as seen in the ip-groups.json file, to extract information for
REGION = "us-east-1"

# Name of the service, as seen in the ip-groups.json file, to extract information for
SERVICE_CF = "CLOUDFRONT"
SERVICE_AZN = "AMAZON"

# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = {'Http': 80, 'Https': 443}
EGRESS_PORTS = {'Http': 80, 'Https': 443, 'Submission': 587}

# Tags which identify the security groups you want to update
SECURITY_GROUP_TAG_FOR_INGRESS_CF_HTTP = {'Name': 'cloudfront', 'AutoUpdate': 'true', 'Traffic': 'ingress',
                                          'Protocol': 'http'}
SECURITY_GROUP_TAG_FOR_INGRESS_CF_HTTPS = {'Name': 'cloudfront', 'AutoUpdate': 'true', 'Traffic': 'ingress',
                                           'Protocol': 'https'}
SECURITY_GROUP_TAG_FOR_EGRESS_AZN_HTTP = {'Name': 'amazon', 'AutoUpdate': 'true', 'Traffic': 'egress',
                                          'Protocol': 'http'}
SECURITY_GROUP_TAG_FOR_EGRESS_AZN_HTTPS = {'Name': 'amazon', 'AutoUpdate': 'true', 'Traffic': 'egress',
                                           'Protocol': 'https'}
SECURITY_GROUP_TAG_FOR_EGRESS_AZN_SUBMISSION = {'Name': 'amazon', 'AutoUpdate': 'true', 'Traffic': 'egress',
                                                'Protocol': 'submission'}


def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # update the security groups
    result = update_security_groups(ip_ranges)

    return result


def get_ip_groups_json(url, expected_hash):
    print("Updating from " + url)

    response = urllib2.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json


def get_ranges_for_service(ranges, region, service):
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['region'] == region:
            if prefix['service'] == service:
                print('Found ' + service + ' range: ' + prefix['ip_prefix'])
                service_ranges.append(prefix['ip_prefix'])

    # AWS EC2 Security Groups are limited to 50 rules
    if (len(service_ranges) > 50):
        # Attempt to condense IP ranges
        service_ranges = condense_ip_list(service_ranges)

    return service_ranges


def update_security_groups(ip_ranges):
    client = boto3.client('ec2')

    # extract the service ranges
    new_ranges_cf = get_ranges_for_service(ip_ranges, REGION, SERVICE_CF)
    new_ranges_azn = get_ranges_for_service(ip_ranges, REGION, SERVICE_AZN)

    ingress_cf_http_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_INGRESS_CF_HTTP)
    ingress_cf_https_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_INGRESS_CF_HTTPS)
    egress_azn_http_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_EGRESS_AZN_HTTP)
    egress_azn_https_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_EGRESS_AZN_HTTPS)
    egress_azn_submission_group = get_security_groups_for_update(client, SECURITY_GROUP_TAG_FOR_EGRESS_AZN_SUBMISSION)
    print ('Found ' + str(len(ingress_cf_http_group)) + ' IngressCfHttpSecurityGroups to update')
    print ('Found ' + str(len(ingress_cf_https_group)) + ' IngressCfHttpsSecurityGroups to update')
    print ('Found ' + str(len(egress_azn_http_group)) + ' EgressAznHttpSecurityGroups to update')
    print ('Found ' + str(len(egress_azn_https_group)) + ' EgressAznHttpsSecurityGroups to update')
    print ('Found ' + str(len(egress_azn_submission_group)) + ' EgressAznSubmissionSecurityGroups to update')

    result = list()
    ingress_cf_http_updated = 0
    ingress_cf_https_updated = 0
    egress_azn_http_updated = 0
    egress_azn_https_updated = 0
    egress_azn_submission_updated = 0

    for group in ingress_cf_http_group:
        if update_security_group(client, group, new_ranges_cf, 'Ingress', INGRESS_PORTS['Http']):
            ingress_cf_http_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in ingress_cf_https_group:
        if update_security_group(client, group, new_ranges_cf, 'Ingress', INGRESS_PORTS['Https']):
            ingress_cf_https_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in egress_azn_http_group:
        if update_security_group(client, group, new_ranges_azn, 'Egress', EGRESS_PORTS['Http']):
            egress_azn_http_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in egress_azn_https_group:
        if update_security_group(client, group, new_ranges_azn, 'Egress', EGRESS_PORTS['Https']):
            egress_azn_https_updated += 1
            result.append('Updated ' + group['GroupId'])
    for group in egress_azn_submission_group:
        if update_security_group(client, group, new_ranges_azn, 'Egress', EGRESS_PORTS['Submission']):
            egress_azn_submission_updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(ingress_cf_http_updated) + ' of ' + str(
        len(ingress_cf_http_group)) + ' IngressCfHttpSecurityGroups')
    result.append('Updated ' + str(ingress_cf_https_updated) + ' of ' + str(
        len(ingress_cf_https_group)) + ' IngressCfHttpsSecurityGroups')
    result.append('Updated ' + str(egress_azn_http_updated) + ' of ' + str(
        len(egress_azn_http_group)) + ' EgressAznHttpSecurityGroups')
    result.append('Updated ' + str(egress_azn_https_updated) + ' of ' + str(
        len(egress_azn_https_group)) + ' EgressAznHttpsSecurityGroups')
    result.append('Updated ' + str(egress_azn_submission_updated) + ' of ' + str(
        len(egress_azn_submission_group)) + ' EgressAznSubmissionSecurityGroups')

    return result


def update_security_group(client, group, new_ranges, traffic, port):
    added = 0
    removed = 0

    if (traffic == 'Egress'):
        sg_rule_list = 'IpPermissionsEgress'
    else:
        sg_rule_list = 'IpPermissions'

    if len(group[sg_rule_list]) > 0:
        for permission in group[sg_rule_list]:
            if permission['FromPort'] <= port and permission['ToPort'] >= port:
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for range in permission['IpRanges']:
                    cidr = range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(range)
                        print(group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort']))

                for range in new_ranges:
                    if old_prefixes.count(range) == 0:
                        to_add.append({'CidrIp': range})
                        print(group['GroupId'] + ": Adding " + range + ":" + str(permission['ToPort']))

                removed += revoke_permissions(client, group, traffic, permission, to_revoke)
                added += add_permissions(client, group, traffic, permission, to_add)
    else:
        to_add = list()
        for range in new_ranges:
            to_add.append({'CidrIp': range})
            print(group['GroupId'] + ": Adding " + range + ":" + str(port))
        permission = {'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
        added += add_permissions(client, group, traffic, permission, to_add)

    print (group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed))
    return (added > 0 or removed > 0)


def revoke_permissions(client, group, traffic, permission, to_revoke):
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        if (traffic == 'Egress'):
            client.revoke_security_group_egress(GroupId=group['GroupId'], IpPermissions=[revoke_params])
        else:
            client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)


def add_permissions(client, group, traffic, permission, to_add):
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        if (traffic == 'Egress'):
            client.authorize_security_group_egress(GroupId=group['GroupId'], IpPermissions=[add_params])
        else:
            client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)


def get_security_groups_for_update(client, security_group_tag):
    filters = list();
    for key, value in security_group_tag.iteritems():
        filters.extend(
            [
                {'Name': "tag-key", 'Values': [key]},
                {'Name': "tag-value", 'Values': [value]}
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']


def condense_ip_list(ip_ranges):
    # Summarizing list of addresses and subnets
    # http://netaddr.readthedocs.io/en/latest/tutorial_01.html

    # List of large Amazon net blocks. Verify via ARIN website.
    ip_list = [
        IPNetwork('3.0.0.0/9'),
        IPNetwork('3.224.0.0/12'),
        IPNetwork('13.248.0.0/14'),
        IPNetwork('15.221.0.0/16'),
        IPNetwork('15.230.0.0/16'),
        IPNetwork('18.128.0.0/9'),
        # IPNetwork('23.20.0.0/14'),
        IPNetwork('34.192.0.0/10'),
        IPNetwork('50.16.0.0/14'),
        IPNetwork('52.0.0.0/11'),
        IPNetwork('52.32.0.0/11'),
        IPNetwork('52.64.0.0/12'),
        IPNetwork('52.84.0.0/14'),
        IPNetwork('52.88.0.0/13'),
        IPNetwork('52.119.128.0/17'),
        IPNetwork('52.144.128.0/17'),
        IPNetwork('52.192.0.0/11'),
        # IPNetwork('54.72.0.0/13'),
        IPNetwork('54.80.0.0/12'),
        IPNetwork('54.144.0.0/12'),
        IPNetwork('54.160.0.0/12'),
        IPNetwork('54.192.0.0/12'),
        IPNetwork('54.224.0.0/12'),
        IPNetwork('54.240.192.0/18'),
        IPNetwork('64.252.64.0/18'),
        IPNetwork('99.77.128.0/17'),
        IPNetwork('99.82.0.0/16'),
        IPNetwork('150.222.0.0/16'),
        IPNetwork('176.32.120.0/21'),
        IPNetwork('184.72.0.0/15'),
        IPNetwork('205.251.192.0/18'),
        IPNetwork('216.182.224.0/20')
    ]

    for range in ip_ranges:
        # print("Adding " + range)
        ip_list.append(IPNetwork(range))

    # Merge known Amazon blocks with published Amazon blocks
    ip_ranges_condensed = cidr_merge(ip_list)

    # Convert results to strings
    ip_list_condensed = []
    for range in ip_ranges_condensed:
        ip_list_condensed.append(str(range))

    # Summary of results
    print("Range Count Published by Amazon: " + str(len(ip_ranges)))
    # print(ip_ranges)
    print("Range Count Condensed: " + str(len(ip_list_condensed)))
    # print(ip_list_condensed)

    return ip_list_condensed


'''
Sample Event From SNS:
{
  "Records": [
    {
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
      "EventSource": "aws:sns",
      "Sns": {
        "SignatureVersion": "1",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"03a8199d0c03ddfec0e542f8bf650ee7\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}

'''
