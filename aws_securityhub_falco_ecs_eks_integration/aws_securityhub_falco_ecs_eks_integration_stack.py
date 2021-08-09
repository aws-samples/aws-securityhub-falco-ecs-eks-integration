from aws_cdk import core as cdk
from aws_cdk import aws_lambda as _lambda
from aws_cdk import aws_iam as iam

# For consistency with other languages, `cdk` is the preferred import name for
# the CDK's core module.  The following line also imports it as `core` for use
# with examples from the CDK Developer's Guide, which are in the process of
# being updated to use `cdk`.  You may delete this import if you don't need it.
from aws_cdk import core


class AwsSecurityhubFalcoEcsEksIntegrationStack(cdk.Stack):

    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        custom_role = iam.Role(self, "CustomRole",assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"))
        custom_role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"))

        # create lambda function
        function = _lambda.Function(self, "lambda_function",
                                    runtime=_lambda.Runtime.PYTHON_3_7,
                                    handler="falco-security-hub-int.lambda_handler",
                                    code=_lambda.Code.asset("./lambda"),
                                    role = custom_role)
                                    
        custom_role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["ec2:DescribeInstances"]
        ))
        
        custom_role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["ecs:DescribeTasks"]
        ))

        custom_role.add_to_policy(iam.PolicyStatement(
            resources=["*"],
            actions=["securityhub:BatchImportFindings"]
        ))
