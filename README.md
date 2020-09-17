# Update Security Groups using AWS ip-ranges.json File

This Python code runs as an AWS Lambda Function that automatically downloads the published AWS IP Ranges and updates IP ranges in EC2 Security Groups that contain special tags each time new AWS IP Ranges are updated.

This code is especially helpful if you need to maintain a Security Group in one of these scenarios:
1. Only allow inbound HTTPS traffic (443/tcp) from CloudFront IP addresses
1. Only allow outbound HTTPS traffic (443/tcp) to known AWS IP addresses (e.g. SQS\*)
1. Only allow outbound SUBMISSION traffic (587/tcp) to known AWS IP addresses (e.g. SES\*)

 \* Be aware AWS IP list does not identify ranges used exclusively for SQS or SES. We are able to restrict outbound traffic to known AWS IP addresses that would included SQS or SES, but would also include many other AWS services, including EC2 services belonging to other customers!

## Setup Instructions

1. Create one or more Security Groups for your particular needs. Examples below.

    The following security group will be updated with IP ranges with service name "cloudfront".

    Security Group Name: "Inbound: HTTPS from AWS CloudFront" (any name is allowed here)
     * Tag name "AutoUpdate" value "true"
     * Tag name "Protocol" value "https"
     * Tag name "Traffic" value "ingress"
     * Tag name "Name" value "cloudfront"

    The following 2 security groups will be updated with IP ranges with service name "amazon". Be aware this is nearly the entire AWS IP range and includes many different services, including EC2 IP addresses for other customers! This is a very large list with 241 ranges for us-east-1 as of 09/2020, so our script consolidates and combines ranges using manual and automatic techniques. Be aware several large IP ranges are hard-coded into the script to improve the consolidation, with the side effect of allowing small % of non-AWS IP addresses. This effectively reduces the list of 241 ranges down to 56 ranges for us-east-1 as of 09/2020.

    Security Group Name: "Outbound: HTTPS to AWS" (any name is allowed here)
     * Tag name "AutoUpdate" value "true"
     * Tag name "Protocol" value "https"
     * Tag name "Traffic" value "egress"
     * Tag name "Name" value "amazon"

    Security Group Name: "Outbound: SUBMISSION to AWS" (any name is allowed here)
     * Tag name "AutoUpdate" value "true"
     * Tag name "Protocol" value "submission"
     * Tag name "Traffic" value "egress"
     * Tag name "Name" value "amazon"

    If you intend to maintain one of these large Security Groups with 58 address ranges, confirm your AWS account is configured to allow 60 rules per Security Group. If you can only add 5 Security Groups to an interface, your account still has the default settings and should already allow 60 rules per Security Group.
    https://aws.amazon.com/premiumsupport/knowledge-center/increase-security-group-rule-limit/

1. Create a Role for your Lambda Function

    ```
    arn:aws:iam::123456789012:role/Lambda-Security-Group-Update-AWS-IPs
    ```

1. Attach a Policy to your Role. Refer to policy file.

    policy-security-group-auto-update-aws-ips.json

1. Create a Lambda Function. Refer to code file. You will also need to import `netaddr` into your Lambda environment. This code is tested with netaddr 0.7.19.

    update_security_groups.py

1. Download JSON file and calculate MD5

    ```
    wget https://ip-ranges.amazonaws.com/ip-ranges.json
    md5sum ip-ranges.json
    5302033d9f139fc8f92b87cd5b957fbd
    ```

1. Create Test Event with current MD5 (e.g. "TestInvokeViaSNS") and run test to update Security Groups.

```
{
  "Records": [
    {
      "EventSource": "aws:sns",
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged",
      "Sns": {
        "Type": "Notification",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "TopicArn": "arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged",
        "Subject": "TestInvoke",
        "Message": "{\"create-time\": \"2019-12-31T23:59:59+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"5302033d9f139fc8f92b87cd5b957fbd\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "SignatureVersion": "1",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "UnsubscribeUrl": "EXAMPLE",
        "MessageAttributes": {
          "Test": {
            "Type": "String",
            "Value": "TestString"
          },
          "TestBinary": {
            "Type": "Binary",
            "Value": "TestBinary"
          }
        }
      }
    }
  ]
}
```

1. Add Lambda Trigger and subscribe to the official SNS notification for AWS IP Range updates

    ```
    arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged
    ```

Your Security Groups should be automatically updated each time AWS IP Range JSON file is updated.


## TROUBLESHOOTING

1. An error occurred (RulesPerSecurityGroupLimitExceeded) when calling the AuthorizeSecurityGroupEgress operation: The maximum number of rules per security group has been reached.

    Ensure your AWS account allows up to 60 rules per Security Group. Learn more here:
    https://aws.amazon.com/premiumsupport/knowledge-center/increase-security-group-rule-limit/

    It is likely that the number of AWS IP ranges for a given region will exceed 60 in the near future, even with our manual and automatic consolidation of the IP ranges.

    * You could more aggressively combine IP ranges by defining larger manual ranges (e.g. I recently combined 18.204.0.0/14, 18.208.0.0/13, 18.232.0.0/14 into 18.128.0.0/9, after confirming the entire 18.128.0.0/9 range is operated by AWS).

    * You could update the script to ignore ranges. For example, some ranges are associated with us-east-1 but are actually operated by RIPE (European IP Registry), and could possibly be excluded.

    * You could increase your maximum Rules per Security Group to 75 by limiting the number of Security Groups on an interface to 4 SGs.

1. MD5 Mismatch: got 2e967e943cf98ae998efeec05d4f351c expected 7fd59f5c7f5cf643036cbd4443ad3e4b: Exception

    You will receive this error if you are attempting to test your function, but the message in your test notification includes an incorrect MD5 hash. You must manually download the JSON file and calculate the current MD5 file hash, then update the message in your test to include the current MD5 file hash.

    ```
    wget https://ip-ranges.amazonaws.com/ip-ranges.json
    md5sum ip-ranges.json
    ```
