from cloud_inquisitor import get_aws_session, AWS_REGIONS
from cloud_inquisitor.config import dbconfig, ConfigOption
from cloud_inquisitor.constants import NS_AUDITOR_VPC_FLOW_LOGS, AccountTypes
from cloud_inquisitor.plugins import BaseAuditor
from cloud_inquisitor.schema import Account, AuditLog
from cloud_inquisitor.utils import get_template
from cloud_inquisitor.wrappers import retry


class VPCFlowLogsAuditor(BaseAuditor):
    name = 'VPC Flow Log Compliance'
    ns = NS_AUDITOR_VPC_FLOW_LOGS
    enabled = dbconfig.get('enabled', ns, False)
    interval = dbconfig.get('interval', ns, 60)
    start_delay = 0
    options = (
        ConfigOption('enabled', False, 'bool', 'Enable the VPC Flow Logs auditor'),
        ConfigOption('interval', 60, 'int', 'Run frequency in minutes')
    )

    def __init__(self):
        super().__init__()
        self.session = None

    def run(self):
        """Main entry point for the auditor worker.

        Args:
            *args:
            **kwargs:

        Returns:
            `None`
        """
        # Loop through all accounts that are marked as enabled
        for account in Account.query.filter(Account.enabled == 1, Account.account_type == AccountTypes.AWS).all():
            self.log.debug('Now Working through account {}'.format(account))
            self.session = get_aws_session(account)

            # Check and create role w/ policy if it doesn't exist. We need the RoleARN to create the flowlogs.
            role_arn = self.get_iam_role_arn(account, self.session)
            arn = role_arn if role_arn else self.create_iam_role(account, self.session)

            for aws_region in AWS_REGIONS:
                try:
                    all_vpcs = self.list_vpcs(account, aws_region, self.session)
                    flow_exist_status = self.check_vpc(account, aws_region, self.session)

                    # Get a unique list of VPC-IDs that doesn't have flow logging enabled
                    need_vpc_flow = list(set(all_vpcs) - set(flow_exist_status))
                    if need_vpc_flow:
                        self.log.debug('Creating Flow Logs for the following vpcs: {}'.format(
                            ', '.join(need_vpc_flow)
                        ))
                        for flow in need_vpc_flow:
                            # A CloudWatch Log Group is currently required to create the VPC Flow log
                            try:
                                if self.create_cw_log(account, aws_region, flow, self.session):
                                    self.create_vpc_flow(account, aws_region, flow, arn, self.session)

                            except Exception:
                                self.log.exception(
                                    'Couldnt Configure Flow Logs for {} for account {} and region {}.'.format(
                                        flow,
                                        account,
                                        aws_region
                                    )
                                )

                    else:
                        self.log.debug('Nothing created for region {}'.format(aws_region))
                except Exception:
                    self.log.exception('There was a problem parsing VPCs for account {} and region {}.'.format(
                        account,
                        aws_region
                    ))

    @retry
    def get_iam_role_arn(self, account):
        """Return the ARN of the IAM Role on the provided account as a string. Returns an `IAMRole` object from boto3

        Args:
            account (:obj:`Account`): Account where to locate the role

        Returns:
            :obj:`IAMRole`
        """
        marker = None
        try:
            iam = self.session.client('iam')
            while True:
                if marker:
                    roles = iam.list_roles(Marker=marker)
                else:
                    roles = iam.list_roles()

                for item in roles['Roles']:
                    if item['RoleName'] == 'VpcFlowLogsRole':
                        return iam.get_role(RoleName='VpcFlowLogsRole')['Role']['Arn']

                if roles['IsTruncated']:
                    marker = roles['Marker']
                else:
                    break

            return None

        except Exception:
            self.log.exception(
                'Problem enumerating roles for account {}. Check the permissions for this account.'.format(account))

    @retry
    def create_iam_role(self, account):
        """Create a new IAM role. Returns the ARN of the newly created role

        Args:
            account (:obj:`Account`): Account where to create the IAM role

        Returns:
            `str`
        """
        try:
            iam = self.session.client('iam')
            trusttmpl = get_template('vpc_flow_logs_iam_role_trust.json')
            policytmpl = get_template('vpc_flow_logs_role_policy.json')
            trust = trusttmpl.render()
            policy = policytmpl.render()

            AuditLog.log(
                event='vpc_flow_logs.create_iam_role',
                actor=self.ns,
                data={
                    'account': account.account_name,
                    'roleName': 'VpcFlowLogsRole',
                    'trustRelationship': trust,
                    'inlinePolicy': policy
                }
            )

            newrole = iam.create_role(
                Path='/',
                RoleName='VpcFlowLogsRole',
                AssumeRolePolicyDocument=trust
            )

            # Attach an inline policy to the role to avoid conflicts or hitting the Managed Policy Limit
            iam.put_role_policy(
                RoleName='VpcFlowLogsRole',
                PolicyName='VpcFlowPolicy',
                PolicyDocument=policy
            )

            self.log.debug('Role and policy created successfully')
            return newrole['Role']['Arn']

        except Exception:
            self.log.exception('There was a problem creating the IAM role for account {}.'.format(account))

    @retry
    def list_vpcs(self, account, region):
        """List all VPCs for a given account and region. Returns a `list` of VPC Id's

        Args:
            account (:obj:`Account`): Account to list VPCs for
            region (`str`): Region to list VPCs for

        Returns:
            :obj:`list` of `str`
        """
        try:
            ec2 = self.session.client('ec2', region)
            return [vpc['VpcId'] for vpc in ec2.describe_vpcs().get('Vpcs')]
        except:
            self.log.exception('Problem finding VPCs for {} / {}.'.format(account, region))

    @retry
    def check_vpc(self, account, region):
        """Check if there is an existing VPC Flow log. Returns a `list` of the resource id of the flows found

        Args:
            account (:obj:`Account`): Account to locate flow logs in
            region (str): Region to locate flow logs in

        Returns:
            :obj:`list` of `str`
        """
        # Check if we have a VPC Flow log existing
        try:
            vpc = self.session.client('ec2', region)
            allflowlogs = vpc.describe_flow_logs()
            vpc_flow_enabled = []

            # Just iterate through the flow logs and display them if they exist
            if allflowlogs['FlowLogs']:
                for item in allflowlogs['FlowLogs']:
                    vpc_flow_enabled.append(item['ResourceId'])
            else:
                self.log.debug('No Flow logs detected for region {}'.format(region))

            return vpc_flow_enabled

        except Exception:
            self.log.exception(
                'Error while listing VPC Flow logs for {} / {}.'.format(
                    account,
                    region
                )
            )

    @retry
    def create_cw_log(self, account, region, vpcname):
        """Create a new CloudWatch log group based on the VPC Name. Returns `True` if succesful

        Args:
            account (:obj:`Account`): Account to create the log group in
            region (`str`): Region to create the log group in
            vpcname (`str`): Name of the VPC the log group is fow

        Returns:
            `bool`
        """
        try:
            AuditLog.log(
                event='vpc_flow_logs.create_cloudwatch_logs',
                actor=self.ns,
                data={
                    'account': account.account_name,
                    'region': region,
                    'vpcName': vpcname
                }
            )
            cw = self.session.client('logs', region)
            if vpcname not in [x['logGroupName'] for x in cw.describe_log_groups().get('logGroups')]:
                cw.create_log_group(logGroupName=vpcname)
                self.log.info('Log Group {} has been created.'.format(vpcname))

            return True

        except Exception:
            self.log.exception('There was a problem creating CloudWatch LogStream for {} / {}.'.format(
                account,
                region
            ))

    @retry
    def create_vpc_flow(self, account, region, vpc_id, iam_role_arn):
        """Create a new VPC Flow log

        Args:
            account (:obj:`Account`): Account to create the flow in
            region (`str): Region to create the flow in
            vpc_id (`str`): ID of the VPC to create the flow for
            iam_role_arn (`str): ARN of the IAM role used to post logs to the log group

        Returns:
            `None`
        """
        try:
            AuditLog.log(
                event='vpc_flow_logs.create_vpc_flow',
                actor=self.ns,
                data={
                    'account': account.account_name,
                    'region': region,
                    'vpcId': vpc_id,
                    'arn': iam_role_arn
                }
            )
            flow = self.session.client('ec2', region)
            flow.create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType='VPC',
                TrafficType='ALL',
                LogGroupName=vpc_id,
                DeliverLogsPermissionArn=iam_role_arn
            )
            self.log.info('VPC Logging has been enabled for {}'.format(vpc_id))

        except Exception:
            self.log.exception('There was a problem creating the VPC Flow for account {} region {}.'.format(
                account,
                region
            ))
