#!/usr/bin/env python3
"""
NetBox IP Address Sync Script (Custom Script for NetBox UI)

Reads IP addresses from a JSON file stored in NetBox Datasources:
- Datasources should be configured in Operations → Datasources
- JSON files are stored in /opt/netbox/data/ directory
- Creates new IP addresses if they don't exist
- Updates existing IP addresses if they already exist
- Uses NetBox ORM models instead of API calls (more efficient)
- Runs from NetBox UI under Customization > Scripts
"""

import json
import os
from extras.scripts import Script, ChoiceVar, StringVar, BooleanField
from ipam.models import IPAddress
from dcim.models import Device, Interface
from virtualization.models import VirtualMachine, VMInterface


class NetBoxIPSync(Script):
    """Sync IP addresses from JSON Datasource to NetBox"""

    def get_datasources():
        """Dynamically get available datasources from NetBox"""
        from extras.models import DataSource
        datasources = DataSource.objects.all().values_list("name", "name")
        return tuple(datasources) if datasources else ()

    datasource = ChoiceVar(
        label="Datasource",
        description="Select the datasource containing the JSON file with IP addresses",
        choices=get_datasources,
        required=True
    )

    json_file_name = StringVar(
        label="JSON File Name",
        description="Name of the JSON file in the datasource (e.g., 'ip_addresses.json')",
        required=True
    )

    dry_run = BooleanField(
        label="Dry Run",
        description="Preview changes without applying them",
        default=False
    )

    class Meta:
        name = "IP Address Sync from Datasource"
        description = "Sync IP addresses from JSON file in NetBox Datasource"
        ordering = ("name",)

    def load_json_from_datasource(self, datasource_name, json_file_name):
        """Read and parse JSON from NetBox Datasource"""
        from extras.models import DataSource

        try:
            # Get the datasource object
            datasource = DataSource.objects.get(name=datasource_name)

            # NetBox stores datasources in /opt/netbox/data/ with files in 'files' subdir
            data_base_path = "/opt/netbox/data"
            datasource_dir = os.path.join(data_base_path, datasource_name)

            if not os.path.exists(datasource_dir):
                raise FileNotFoundError(f"Datasource directory not found: {datasource_dir}")

            # Construct full path to JSON file
            json_path = os.path.join(datasource_dir, json_file_name)

            if not os.path.exists(json_path):
                # Check in the 'files' subdirectory (common pattern)
                files_dir = os.path.join(datasource_dir, "files")
                if os.path.exists(files_dir):
                    for root, dirs, files in os.walk(files_dir):
                        for file in files:
                            if file == json_file_name:
                                json_path = os.path.join(root, file)
                                break

            if not os.path.exists(json_path):
                raise FileNotFoundError(f"JSON file not found: {json_path}")

            with open(json_path, 'r') as f:
                data = json.load(f)

            # Validate structure
            if not isinstance(data, list):
                raise ValueError("JSON file must contain a list of IP address objects")

            return data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
        except DataSource.DoesNotExist:
            raise ValueError(f"Datasource '{datasource_name}' does not exist")

    def get_or_create_ip_address(self, ip_address, description, dry_run=False):
        """Get existing IP or create new one, update description if needed"""
        try:
            # Check if IP already exists
            existing_ip = IPAddress.objects.filter(address=ip_address).first()

            if existing_ip:
                # Check if update is needed
                needs_update = (
                        existing_ip.description != description or
                        existing_ip.status.name != 'active'
                )
                if needs_update:
                    if not dry_run:
                        existing_ip.description = description
                        existing_ip.status_id = 'active'  # active status ID
                        existing_ip.save()
                        self.log_success(f"Updated existing IP: {ip_address}")
                        return True, "updated"
                    else:
                        self.log_warning(f"[DRY-RUN] Would update existing IP: {ip_address}")
                        return True, "updated"
                else:
                    self.log_info(f"No changes needed for IP: {ip_address}")
                    return False, "skipped"
            else:
                if not dry_run:
                    IPAddress.objects.create(
                        address=ip_address,
                        status_id='active',
                        description=description
                    )
                    self.log_success(f"Created new IP: {ip_address}")
                    return True, "created"
                else:
                    self.log_warning(f"[DRY-RUN] Would create new IP: {ip_address}")
                    return True, "created"

        except Exception as e:
            self.log_failure(f"Error processing IP {ip_address}: {e}")
            return False, "error"

    def run(self, data, commit=True):
        """Main execution function for NetBox custom script"""
        datasource_name = data['datasource']
        json_file_name = data['json_file_name']
        dry_run = data['dry_run']

        # Load JSON data from datasource
        self.log_info(f"Loading IP addresses from datasource '{datasource_name}', file '{json_file_name}'...")
        try:
            ip_list = self.load_json_from_datasource(datasource_name, json_file_name)
            self.log_success(f"Loaded {len(ip_list)} IP address entries")
        except Exception as e:
            self.log_failure(f"Failed to load JSON from datasource: {e}")
            return

        # Track statistics
        created_count = 0
        updated_count = 0
        skipped_count = 0
        error_count = 0

        self.log_info(f"Processing {len(ip_list)} IP addresses...")

        for ip_entry in ip_list:
            ip_address = ip_entry.get('ip')
            description = ip_entry.get('description', '')

            if not ip_address:
                self.log_warning("Skipping entry - missing 'ip' field")
                skipped_count += 1
                continue

            self.log_info(f"Processing IP: {ip_address}")

            changed, action = self.get_or_create_ip_address(ip_address, description, dry_run)

            if action == "created":
                created_count += 1
            elif action == "updated":
                updated_count += 1
            elif action == "skipped":
                skipped_count += 1
            else:
                error_count += 1

        # Summary
        self.log_success("Sync completed!")
        self.log_success(f"Created: {created_count}")
        self.log_success(f"Updated: {updated_count}")
        self.log_success(f"Skipped: {skipped_count}")
        self.log_success(f"Errors: {error_count}")

        if dry_run:
            self.log_info("This was a dry run - no changes were saved.")


# Register the script for NetBox
script = NetBoxIPSync
