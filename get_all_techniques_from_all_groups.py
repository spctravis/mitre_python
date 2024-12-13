from mitreattack.stix20 import MitreAttackData
from datetime import datetime, timezone
import os
import re
from collections import defaultdict

def sanitize_filename(name):
    # Replace spaces with underscores and remove invalid characters
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', name.replace(" ", "_"))

def main():
    mitre_attack_data = MitreAttackData("enterprise-attack.json")

    groups = mitre_attack_data.get_groups(remove_revoked_deprecated=True)

    for group in groups:
        if group.aliases:
            first_alias = group.aliases[0]
        else:
            first_alias = group.name  # Fallback if no aliases are present
        sanitized_name = sanitize_filename(first_alias)
        filename = f"{sanitized_name}.txt"
        
        with open(filename, 'w') as file:
            file.write(f"{group.name} ({mitre_attack_data.get_attack_id(group.id)})\n")
            # Write the description of the group
            file.write(f"{group.description}\n")
            # Write the aliases of the group
            file.write(f"Aliases: {', '.join(group.aliases)}\n")
            
            group_stix_id = group.id
            techniques_used_by_group = mitre_attack_data.get_techniques_used_by_group(group_stix_id)

            file.write(f"\nTechniques used by {group.name} ({len(techniques_used_by_group)}):\n")

            # Collect all relevant techniques with their created dates and descriptions
            techniques_list = []

            for t in techniques_used_by_group:
                technique = t["object"]
                technique_id = technique.id

                procedure_examples = mitre_attack_data.get_procedure_examples_by_technique(technique_id)
                
                for procedure_example in procedure_examples:
                    source_object = mitre_attack_data.get_object_by_stix_id(procedure_example.source_ref)
                    source_attack_id = mitre_attack_data.get_attack_id(source_object.id)
                    
                    if source_object.name == group.name:
                        created_attr = source_object.created
                        
                        if isinstance(created_attr, datetime):
                            techniques_list.append({
                                "technique_name": technique.name,
                                "technique_id": mitre_attack_data.get_attack_id(technique.id),
                                "source_attack_id": source_attack_id,
                                "description": procedure_example.description,
                                "created_attr": created_attr
                            })
                        else:
                            # Handle cases where created_attr is not a datetime object if necessary
                            pass

            # Group techniques by technique_name
            techniques_by_name = defaultdict(list)
            for tech in techniques_list:
                techniques_by_name[tech["technique_name"]].append(tech)

            # Keep only the latest 5 entries per technique_name
            filtered_techniques = []
            for tech_name, techs in techniques_by_name.items():
                sorted_techs = sorted(techs, key=lambda x: x["created_attr"], reverse=True)
                filtered_techniques.extend(sorted_techs[:5])

            # Optionally, sort the filtered_techniques by created_attr if needed
            sorted_filtered_techniques = sorted(filtered_techniques, key=lambda x: x["created_attr"], reverse=True)

            for tech in sorted_filtered_techniques:
                file.write(f"* {tech['technique_name']} ({tech['technique_id']}) [{tech['source_attack_id']}] : {tech['description']}\n")

if __name__ == "__main__":
    main()
