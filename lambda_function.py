"""
Author: yuki.hirano
Summerize Inspector Findings Function
"""
import os
import boto3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import pprint


def get_findings(findings_filter):
    """
    Get findings result
    
    :param resources: List of tuples (findings_filter)
    :param findings_filter: Security Hub Findings Filter
    :return: None
    """
    client = boto3.client('securityhub',os.environ.get('AWS_REGION'))
    next_token = None
    while True:
        if next_token:
            response = client.get_findings(
                Filters=findings_filter,
                MaxResults=100,
                NextToken=next_token
            )
        else:
            response = client.get_findings(
                Filters=findings_filter,
                MaxResults=100
            )
        yield from response['Findings']
        next_token = response.get('NextToken')
        if not next_token:
            break

def summarize_vulnerabilities( findings_filter, lang='en'):
    """
    Create Summerize Inspector Vulnerabilities
    
    :param resources: List of tuples (findings_filter)
    :param findings_filter: Security Hub Findings Filter
    :return: stt summary string
    """
    
    ec2_vulnerabilities = defaultdict(list)
    lambda_vulnerabilities = defaultdict(list)
    vulnerabilities = defaultdict(dict)
    
    for finding in get_findings(findings_filter):
        resource_type = finding.get('Resources', [{}])[0].get('Type', '')
        resource_id = finding.get('Resources', [{}])[0].get('Id', '')
        title = finding.get('Title', '')
        severity = finding.get('Severity', {}).get('Label', 'UNKNOWN')
        for Vulnerabilitie in finding.get('Vulnerabilities',''):
            vulnerabilities[Vulnerabilitie.get('Id')] = {
                "Vulnerabilities_Vendor": Vulnerabilitie.get('Vendor').get('Name',''),
                "Vulnerabilities_Url": Vulnerabilitie.get('Vendor').get('Url',''),
                "Vulnerabilities_ReferenceUrls":Vulnerabilitie.get('ReferenceUrls','')
            }
        if resource_type == 'AwsEc2Instance':
            if resource_id not in ec2_vulnerabilities.keys():
                ec2_vulnerabilities[resource_id] = defaultdict(dict)
                ec2_vulnerabilities[resource_id]['Name'] = finding.get('Resources', [{}])[0].get('Tags', {'Name':''}).get('Name', '')
                ec2_vulnerabilities[resource_id]['Vulnerabilities'] = []
            ec2_vulnerabilities[resource_id]['Vulnerabilities'].append((title, severity))
        elif resource_type == 'AwsLambdaFunction':
            if resource_id not in lambda_vulnerabilities.keys():
                lambda_vulnerabilities[resource_id] = defaultdict(dict)
                lambda_vulnerabilities[resource_id]['Name'] = finding.get('Resources', [{}])[0].get('Details',[{}]).get('AwsLambdaFunction', {}).get('FunctionName', '')
                lambda_vulnerabilities[resource_id]['Vulnerabilities'] = []
            lambda_vulnerabilities[resource_id]['Vulnerabilities'].append((title, severity))

    output = []
    output.append('# EC2インスタンスの脆弱性サマリー:' if lang == 'jp' else '# EC2 Instance Vulnerability Summary')
    for arn in ec2_vulnerabilities.keys():
        output.append(f"## インスタンスID: {arn}" if lang == 'jp' else f"## EC2 Instance ID: {arn}")
        output.append(f"### Nameタグ: {ec2_vulnerabilities[arn].get('Name','')}"  if lang == 'jp' else f"## Value of Name tag: {ec2_vulnerabilities[arn].get('Name','')}")
        output.append(f"### 脆弱性" if lang == 'jp' else f"### Vulnerability")
        for title, severity in ec2_vulnerabilities[arn]['Vulnerabilities']:
            output.append(f"  - {title} (重要度: {severity})" if lang == 'jp' else f"  - {title} (Severity: {severity})")
        output.append("")
    
    output.append("\n# Lambda関数の脆弱性サマリー:" if lang == 'jp' else "\n# Lambda Function Vulnerability Summary")
    for arn in lambda_vulnerabilities.keys():
        output.append(f"## 関数: {arn}" if lang == 'jp' else f"## Function: {arn}")
        output.append(f"### 関数名: {lambda_vulnerabilities[arn].get('Name','')}" if lang == 'jp' else f"### Function Name: {lambda_vulnerabilities[arn].get('Name','')}")
        output.append(f"### 脆弱性" if lang == 'jp' else f"### Vulnerability")
        for title, severity in lambda_vulnerabilities[arn]['Vulnerabilities']:
            output.append(f"  - {title} (重要度: {severity})" if lang == 'jp' else f"  - {title} (Severity: {severity})")
        output.append("")
    
    output.append("\n# 脆弱性サマリー:" if lang == 'jp' else "\n# Vulnerability Summary")
    for vulnerabilitie_id in vulnerabilities.keys():
        output.append(f"## 脆弱性: {vulnerabilitie_id}" if lang == 'jp' else f"## Vulnerability: {vulnerabilitie_id}")
        output.append(f"   url: {vulnerabilities[vulnerabilitie_id].get('Vulnerabilities_Url')}")
        output.append(f"### ベンダー: {vulnerabilities[vulnerabilitie_id].get('Vulnerabilities_Vendor')}" if lang == 'jp' else f"### Vendor: {vulnerabilities[vulnerabilitie_id].get('Vulnerabilities_Vendor')}" )
        output.append(f"    url: ")
        for url in vulnerabilities[vulnerabilitie_id].get('Vulnerabilities_ReferenceUrls'):
            output.append(f"    - {url} ")
        output.append("")
    return "\n".join(output)
    
def lambda_handler(event, context):
    """
    Lambda Function
        1. Get Security Hub Findings
        2. Create CSV report
    
    :param resources: List of tuples (findings_filter)
    :param findings_filter: Security Hub Findings Filter
    :return: None
    """
    lang = os.environ.get('LANG','en')
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=5)
    end_time_str = end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    start_time_str = start_time.strftime('%Y-%m-%dT%H:%M:%SZ')
    message = summarize_vulnerabilities({
        "AwsAccountId": [
            {
                "Value": "396541092256",
                "Comparison": "EQUALS"
            }
        ],
        "ProductName": [
            {
                "Value": "Inspector",
                "Comparison": "EQUALS"
            }
        ],
        "WorkflowState": [
            {
                "Value": "NEW",
                "Comparison": "EQUALS"
            }
        ],
        "RecordState": [
            {
                "Value": "ACTIVE",
                "Comparison": "EQUALS"
            }
        ],
        "SeverityLabel": [
            {
                "Value": "CRITICAL",
                "Comparison": "EQUALS"
            }
        ],
        'UpdatedAt': [
            {
                'Start': start_time_str,
                'End': end_time_str
            },
        ]
    }, lang = lang)
    subject = u'Inspector メール通知' if lang == 'jp' else 'Inspector Mail Notify'
    client = boto3.client('sns')
    request = {
        'TopicArn': os.environ.get('TOPIC_ARN'),
        'Message': message,
        'Subject': subject
    }
    response = client.publish(**request)
    pprint.pprint(response)
