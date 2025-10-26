from cfnlint.rules import CloudFormationLintRule # pip install cfnlint
from cfnlint.rules import RuleMatch # pip install cfnlint


class InstancePolicy(CloudFormationLintRule):
    id = 'W9003'
    shortdesc = 'Check EC2 instance tags based on instance type'
    description = 'This rule checks for required tags on EC2 instances based on instance type'
    
    def match(self, cfn):
        matches = []
        
        resources = cfn.get_resources(['AWS::EC2::Instance'])
        
        for resource_name, resource in resources.items():
            properties = resource.get('Properties', {})
            instance_type = properties.get('InstanceType')
            tags = properties.get('Tags', [])
            
            tags_dict = {}
            for tag in tags:
                if isinstance(tag, dict) and 'Key' in tag and 'Value' in tag:
                    tags_dict[tag['Key']] = tag['Value']
            
            if instance_type == 't2.micro':
                if not ('FreeTierEligible' in tags_dict and tags_dict['FreeTierEligible'] == 'true'):
                    message = f'EC2 Instance "{resource_name}" of type t2.micro must have a Tag with Key="FreeTierEligible" and Value="true"'
                    matches.append(
                        RuleMatch(
                            ['Resources', resource_name, 'Properties', 'Tags'],
                            message
                        )
                    )
            
            elif instance_type == 'm5.large':
                if not ('PerformanceCritical' in tags_dict and 
                       (tags_dict['PerformanceCritical'] == 'true' or tags_dict['PerformanceCritical'] == 'false')):
                    message = f'EC2 Instance "{resource_name}" of type m5.large must have a Tag with Key="PerformanceCritical" and Value="true" or "false"'
                    matches.append(
                        RuleMatch(
                            ['Resources', resource_name, 'Properties', 'Tags'],
                            message
                        )
                    )
        
        return matches

