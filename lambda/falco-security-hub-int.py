import json
import json 
import boto3
import uuid
import datetime
import base64
import gzip

PARTITION="aws"

session = boto3.session.Session()
ec2 = session.resource("ec2")
sts = session.client('sts')
ecs = session.client('ecs')

def get_ec2_details(instance_id):
        instance = ec2.Instance(instance_id)
        return instance
    
def get_account_id():

    
    caller = sts.get_caller_identity()
    return caller.get("Account")

#https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ecs.html#ECS.Client.describe_tasks
def get_ecs_details(ecs_cluster, ecs_task):
    response = ecs.describe_tasks(cluster=ecs_cluster, tasks=[ecs_task])
    task = response["tasks"][0]
    az = task["availabilityZone"]
    created = task["createdAt"]
    container_resources = []
    for container in task["containers"]:

        resource = {}
        resource["Type"] = "Container"
        resource["Id"] = container["runtimeId"]
        resource["Details"] = {}
        resource["Details"]["Container"] = {}
        resource["Details"]["Other"] = {}
        resource["Details"]["Other"]["containerArn"] = container["containerArn"]
        resource["Details"]["Other"]["taskArn"] = container["taskArn"]
        resource["Details"]["Other"]["containerRuntime"] = container["runtimeId"]
       
       
        resource["Details"]["Container"]["ImageName"] = container["image"]
        if 'imageDigest' in resource:
            resource["Details"]["Container"]["ImageId"] = container["imageDigest"]
        resource["Details"]["Container"]["Name"] = container["name"]

        container_resources.append(resource)

    task_resource = {}
    task_resource["Id"] = task["taskArn"]
    task_resource["Type"] = "Other"
  

    container_resources.append(task_resource)

    cluster_resource = {}
    cluster_resource["Id"] = ecs_cluster
    cluster_resource["Type"] = "Other"

    container_resources.append(cluster_resource)

    return container_resources

#https://falco.org/docs/rules/
def map_finding_severity(priority):

    severity = {
        "EMERGENCY": "CRITICAL",
        "ALERT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "HIGH",
        "NOTICE": "MEDIUM",
        "INFORMATIONAL": "INFORMATIONAL",
        "DEBUG": "INFORMATIONAL"
    }

    label = severity.get(priority.upper(), "INFORMATIONAL")
    sev = {}
    sev["Label"] = label
    sev["Original"] = priority
    return sev


def generate_id(account_id,region):
    suffix = "falco-" + uuid.uuid1().hex
    full_id = f"{region}/{account_id}/{suffix}"
    return full_id


#https://falco.org/docs/rules/
def map_finding_severity(priority):

    severity = {
        "EMERGENCY": "CRITICAL",
        "ALERT": "CRITICAL",
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "WARNING": "HIGH",
        "NOTICE": "MEDIUM",
        "INFORMATIONAL": "INFORMATIONAL",
        "DEBUG": "INFORMATIONAL"
    }

    label = severity.get(priority.upper(), "INFORMATIONAL")
    sev = {}
    sev["Label"] = label
    sev["Original"] = priority
    return sev

def generate_id(account_id,region):
    suffix = "falco-" + uuid.uuid1().hex
    full_id = f"{region}/{account_id}/{suffix}"
    return full_id

def get_ip_address(instance):

    ip = []
    if instance.public_ip_address:
        ip.append(instance.public_ip_address)
    if instance.private_ip_address:
        ip.append(instance.private_ip_address)

    return ip
    
def create_ec2_instance_resource(instance):
    region = session.region_name
    instance_resource = {}
    instance_resource["Details"] = {}
    instance_resource["Type"] = "AwsEc2Instance"
    instance_resource["Id"] = instance.instance_id
    instance_resource["Partition"] = PARTITION
    instance_resource["Region"] = region
    instance_resource["Details"]["AwsEc2Instance"] = {}
    instance_resource["Details"]["AwsEc2Instance"]["Type"] = instance.instance_type
    instance_resource["Details"]["AwsEc2Instance"]["LaunchedAt"] = instance.launch_time.isoformat(timespec='milliseconds')

    ip = get_ip_address(instance)
    
    instance_resource["Details"]["AwsEc2Instance"]["IpV4Addresses"] = ip
    instance_resource["Details"]["AwsEc2Instance"]["SubnetId"] = instance.subnet_id
    instance_resource["Details"]["AwsEc2Instance"]["VpcId"] = instance.vpc_id
    instance_resource["Details"]["AwsEc2Instance"]["IamInstanceProfileArn"] = instance.iam_instance_profile["Arn"]
    
  

    return instance_resource
    
def ecs_convert_falco_log_to_asff(entry):
    region = session.region_name
    instance_id = entry["ec2_instance_id"]
    instance = get_ec2_details(instance_id)
    message = json.loads(entry['log'])
    severity = map_finding_severity(message["priority"])
    account_id= get_account_id()
    this_id = generate_id(account_id,region)

    
    
    instance_resource = create_ec2_instance_resource(instance)
    ecs_resources = get_ecs_details(entry["ecs_cluster"], entry["ecs_task_arn"])
    resources = []
    
    resources.append(instance_resource)

    for container_resource in ecs_resources:
        resources.append(container_resource)

    finding = {}
    finding["SchemaVersion"] = "2018-10-08"
    finding["AwsAccountId"] = account_id
    finding["Id"] = this_id
    finding["Description"] = message["output"]
    finding["GeneratorId"] = instance_id + "-" + this_id.split("/")[-1]
    finding["ProductArn"] = f"arn:{PARTITION}:securityhub:{region}:{account_id}:product/{account_id}/default"
    finding["Severity"] = severity
    finding["Resources"] = resources
    finding["Title"] = message["rule"]
    finding["Types"] = ["Software and Configuration Checks"]
    now = datetime.datetime.now()
    #Lambda is UTC
    finding["UpdatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"
    finding["CreatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"


    return finding



def get_eks_details(message):

    log = message["log"]
    fields = log["output_fields"]

    container_id = fields["container.id"]
    pod_name = fields["k8s.pod.name"]
    namespace = fields["k8s.ns.name"]
    image = fields["container.image.repository"]

    resources = []
    resource = {}
    resource["Type"] = "Container"
    resource["Id"] = container_id
    resource["Details"] = {}
    resource["Details"]["Container"] = {}
    resource["Details"]["Other"] = {}
    resource["Details"]["Other"]["podName"] = pod_name
    resource["Details"]["Other"]["namespaceName"] = namespace
    resource["Details"]["Container"]["ImageName"] = image

    resources.append(resource)
    return resources




def eks_convert_falco_log_to_asff(entry):
    region = session.region_name
    instance_id = entry["ec2_instance_id"]
    instance = get_ec2_details(instance_id)
    
    account_id= get_account_id()
    this_id = generate_id(account_id,region)

    
    output = entry["log"]["output"]
    severity = map_finding_severity(entry["log"]["priority"])

    
    
    instance_resource = create_ec2_instance_resource(instance)
    eks_resources = get_eks_details(entry)
    resources = []
    
    resources.append(instance_resource)

    for container_resource in eks_resources:
        resources.append(container_resource)

    finding = {}
    finding["SchemaVersion"] = "2018-10-08"
    finding["AwsAccountId"] = account_id
    finding["Id"] = this_id
    finding["Description"] = output
    finding["GeneratorId"] = instance_id + "-" + this_id.split("/")[-1]
    finding["ProductArn"] = f"arn:{PARTITION}:securityhub:{region}:{account_id}:product/{account_id}/default"
    finding["Severity"] = severity
    finding["Resources"] = resources
    finding["Title"] = entry["log"]["rule"]
    finding["Types"] = ["Software and Configuration Checks"]
    now = datetime.datetime.now()
    #Lambda is UTC
    finding["UpdatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"
    finding["CreatedAt"] = f"{now.isoformat(timespec='milliseconds')}Z"


    return finding

def lambda_handler(event, context):
    cw_data = event['awslogs']['data']
    data_decoded = base64.b64decode(cw_data)
    data = json.loads(gzip.decompress(data_decoded).decode('utf-8'))
    
    findings = []
    for entry in data['logEvents']:
        message = json.loads(entry['message'])
        if "ecs_cluster" in message:
            finding = ecs_convert_falco_log_to_asff(message)
        else:
            finding = eks_convert_falco_log_to_asff(message)
        findings.append(finding)
    
    sh = session.client('securityhub')
    r = sh.batch_import_findings(Findings=findings)
    
    return