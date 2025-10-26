from cfnlint.rules import CloudFormationLintRule # pip install cfnlint
from cfnlint.rules import RuleMatch # pip install cfnlint


class BucketNamePolicy(CloudFormationLintRule):
    id = 'W9002'
    shortdesc = 'Check RDS deletion policy'
    description = 'This rule checks DeletionPolicy on RDS resources to be Snapshot or Retain'

    def match(self, cfn):
        matches = []
        resources = cfn.get_resources("AWS::S3::Bucket")
        for resource_name, resource in resources.items():
            properties = resource.get('Properties', {})
            bucket_name = properties.get('BucketName')

            # If BucketName exists and does not start with 'btu'
            if isinstance(bucket_name, str) and not bucket_name.startswith('btu'):
                message = f'S3 Bucket "{resource_name}" has BucketName "{bucket_name}" that must start with "btu".'
                matches.append(
                    RuleMatch(
                        ['Resources', resource_name, 'Properties', 'BucketName'],
                        message
                    )
                )

        return matches
