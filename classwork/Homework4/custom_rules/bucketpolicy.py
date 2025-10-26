from cfnlint.rules import CloudFormationLintRule # pip install cfnlint
from cfnlint.rules import RuleMatch # pip install cfnlint


class BucketPolicy(CloudFormationLintRule):
    id = 'W9001'
    shortdesc = 'Check S3 buckets with public access configuration'
    description = 'This rule checks that S3 buckets with any PublicAccessBlockConfiguration property set to false have a PublicAccessAllowed tag with value true'
    
    def match(self, cfn):
        """Check S3 buckets for proper tagging when public access is allowed"""
        matches = []
        
        # Get all S3 bucket resources
        resources = cfn.get_resources(['AWS::S3::Bucket'])
        
        for resource_name, resource in resources.items():
            properties = resource.get('Properties', {})
            public_access_config = properties.get('PublicAccessBlockConfiguration')
            
            # Skip if PublicAccessBlockConfiguration doesn't exist
            if not public_access_config:
                continue
            
            # Check if any property is set to false
            public_access_allowed = False
            for prop, value in public_access_config.items():
                if value is False:
                    public_access_allowed = True
                    break
            
            # If public access is allowed, check for the required tag
            if public_access_allowed:
                tags = properties.get('Tags', [])
                
                # Check if the required tag exists with the correct value
                has_public_access_allowed_tag = False
                for tag in tags:
                    if isinstance(tag, dict) and tag.get('Key') == 'PublicAccessAllowed' and tag.get('Value') == 'true':
                        has_public_access_allowed_tag = True
                        break
                
                # Report violation if the required tag is missing
                if not has_public_access_allowed_tag:
                    path = ['Resources', resource_name, 'Properties', 'Tags']
                    message = f'S3 Bucket "{resource_name}" has public access allowed but is missing the required Tag with Key="PublicAccessAllowed" and Value="true"'
                    matches.append(RuleMatch(path, message))
        
        return matches

