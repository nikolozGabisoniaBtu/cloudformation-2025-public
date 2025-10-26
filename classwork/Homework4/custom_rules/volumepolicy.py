from cfnlint.rules import CloudFormationLintRule
from cfnlint.rules import RuleMatch

class VolumePolicy(CloudFormationLintRule):
    """Check EC2 Volume Tags for gp3 volumes"""
    id = 'W9002'
    shortdesc = 'Check gp3 volumes for Priority tag'
    description = 'This rule checks that gp3 volumes have a Priority tag with value between 3000 and 16000'
    
    def match(self, cfn):
        matches = []
        
        resources = cfn.get_resources(['AWS::EC2::Volume'])
        
        for resource_name, resource in resources.items():
            properties = resource.get('Properties', {})
            volume_type = properties.get('VolumeType')
            
            if not volume_type:
                continue
                
            is_gp3 = False
            
            if volume_type == 'gp3':
                is_gp3 = True
            
            # If this is a gp3 volume, check for the required tag
            if is_gp3:
                tags = properties.get('Tags', [])
                
                # Convert tags to a dictionary for easier checking
                tags_dict = {}
                for tag in tags:
                    if isinstance(tag, dict) and 'Key' in tag and 'Value' in tag:
                        tags_dict[tag['Key']] = tag['Value']
                
                if 'Priority' not in tags_dict:
                    message = f'EC2 Volume "{resource_name}" of type gp3 must have a Tag with Key="Priority" and Value between 3000 and 16000'
                    matches.append(
                        RuleMatch(
                            ['Resources', resource_name, 'Properties', 'Tags'],
                            message
                        )
                    )
                    continue
                
                priority_value = int(tags_dict['Priority'])
                if priority_value < 3000 or priority_value > 16000:
                    message = f'EC2 Volume "{resource_name}" has Priority tag with value {priority_value}, but it must be between 3000 and 16000'
                    matches.append(
                        RuleMatch(
                            ['Resources', resource_name, 'Properties', 'Tags'],
                            message
                        )
                    )
        
        return matches
