#!/usr/bin/env python3
"""
NetBox IP Address & Prefix Sync Script (Custom Script for NetBox UI)

Reads IP addresses and prefixes from JSON files stored in NetBox Datasources:
- Uses ORM models instead of API calls (more efficient)
- Runs from NetBox UI under Customization > Scripts
"""

import json
import os
from extras.scripts import Script, ChoiceVar, StringVar, BooleanField
from ipam.models import IPAddress, Prefix, Role


class NetBoxIPSync(Script):
    """Sync IP addresses and Prefixes from JSON Datasources to NetBox"""

    # Script variable for default datasource
    DEFAULT_DATASOURCE = "default"  # Change this to your default datasource name

    def get_datasources():
        """Dynamically get available datasources from NetBox"""
        from extras.models import DataSource
        datasources = DataSource.objects.all().values_list("name", "name")
        return tuple(datasources) if datasources else ()

    datasource = ChoiceVar(
        label="Datasource",
        description="Select the datasource containing the JSON files",
        choices=get_datasources,
        default=DEFAULT_DATASOURCE,
        required=True
    )

    ip_json_file_name = StringVar(
        label="IP JSON File Name",
        description="Name of the JSON file with IP addresses (e.g., 'ip_addresses.json')",
        required=False
    )

    enable_ip_sync = BooleanField(
        label="Enable IP Sync",
        description="Sync IP addresses from the configured datasource",
        default=True
    )

    prefix_json_file_name = StringVar(
        label="Prefix JSON File Name",
        description="Name of the JSON file with prefixes (e.g., 'prefixes.json')",
        required=False
    )

    enable_prefix_sync = BooleanField(
        label="Enable Prefix Sync",
        description="Sync prefixes from the configured datasource",
        default=True
    )

    dry_run = BooleanField(
        label="Dry Run",
        description="Preview changes without applying them",
        default=False
    )

    class Meta:
        name = "IP Address & Prefix Sync from Datasources"
        description = "Sync IP addresses and prefixes from JSON files in NetBox Datasources"
        ordering = ("name",)

    def load_json_from_datasource(self, datasource_name, json_file_name):
        """Read and parse JSON from NetBox Datasource"""
        from extras.models import DataSource
        import pathlib

        try:
            # Get the datasource object
            datasource = DataSource.objects.get(name=datasource_name)

            # NetBox stores the actual filesystem path in datasource.path
            datasource_dir = pathlib.Path(datasource.path)

            if not datasource_dir.exists():
                raise FileNotFoundError(f"Datasource directory not found: {datasource_dir}")

            # Construct full path to JSON file
            json_path = datasource_dir / json_file_name

            if not json_path.exists():
                raise FileNotFoundError(f"JSON file not found: {json_path}")

            with open(json_path, 'r') as f:
                data = json.load(f)

            # Validate structure
            if not isinstance(data, list):
                raise ValueError("JSON file must contain a list of objects")

            return data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")
        except DataSource.DoesNotExist:
            raise ValueError(f"Datasource '{datasource_name}' does not exist")

    def load_ip_addresses(self, datasource_name, json_file_name):
        """Load IP addresses from datasource"""
        return self.load_json_from_datasource(datasource_name, json_file_name)

    def load_prefixes(self, datasource_name, json_file_name):
        """Load prefixes from datasource"""
        return self.load_json_from_datasource(datasource_name, json_file_name)

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

    def get_or_create_prefix(self, prefix_value, description, role, dry_run=False):
        """Get existing prefix or create new one, update description and role if needed"""
        try:
            # Check if prefix already exists
            existing_prefix = Prefix.objects.filter(prefix=prefix_value).first()

            # Get role object if provided
            role_obj = None
            if role:
                try:
                    role_obj = Role.objects.get(name__iexact=role)
                except Role.DoesNotExist:
                    # Try to create role if it doesn't exist
                    role_obj = Role.objects.create(name=role, slug=role.lower().replace(' ', '-'))
                    self.log_success(f"Created new role: {role}")

            if existing_prefix:
                # Check if update is needed
                needs_update = (
                        existing_prefix.description != description or
                        (role_obj and existing_prefix.role != role_obj)
                )
                if needs_update:
                    if not dry_run:
                        existing_prefix.description = description
                        if role_obj:
                            existing_prefix.role = role_obj
                        existing_prefix.save()
                        self.log_success(f"Updated existing prefix: {prefix_value}")
                        return True, "updated"
                    else:
                        self.log_warning(f"[DRY-RUN] Would update existing prefix: {prefix_value}")
                        return True, "updated"
                else:
                    self.log_info(f"No changes needed for prefix: {prefix_value}")
                    return False, "skipped"
            else:
                if not dry_run:
                    prefix_data = {
                        'prefix': prefix_value,
                        'status_id': 'active',
                        'description': description
                    }
                    if role_obj:
                        prefix_data['role'] = role_obj
                    Prefix.objects.create(**prefix_data)
                    self.log_success(f"Created new prefix: {prefix_value}")
                    return True, "created"
                else:
                    self.log_warning(f"[DRY-RUN] Would create new prefix: {prefix_value}")
                    return True, "created"

        except Exception as e:
            self.log_failure(f"Error processing prefix {prefix_value}: {e}")
            return False, "error"

    def run(self, data, commit=True):
        """Main execution function for NetBox custom script"""
        # Check if we should run any sync operations
        enable_ip_sync = data.get('enable_ip_sync', True)
        enable_prefix_sync = data.get('enable_prefix_sync', True)

        if not enable_ip_sync and not enable_prefix_sync:
            self.log_failure("Both IP and Prefix sync are disabled. Nothing to do.")
            return

        dry_run = data['dry_run']
        datasource_name = data['datasource']

        # Track statistics
        ip_created_count = 0
        ip_updated_count = 0
        ip_skipped_count = 0
        ip_error_count = 0

        prefix_created_count = 0
        prefix_updated_count = 0
        prefix_skipped_count = 0
        prefix_error_count = 0

        # Sync IP addresses if enabled
        if enable_ip_sync:
            ip_json_file_name = data.get('ip_json_file_name')

            if ip_json_file_name:
                # Load JSON data from datasource
                self.log_info(f"Loading IP addresses from datasource '{datasource_name}', file '{ip_json_file_name}'...")
                try:
                    ip_list = self.load_ip_addresses(datasource_name, ip_json_file_name)
                    self.log_success(f"Loaded {len(ip_list)} IP address entries")
                except Exception as e:
                    self.log_failure(f"Failed to load IP addresses from datasource: {e}")
                    ip_error_count = 1
                    return
            else:
                self.log_warning("IP sync enabled but filename not specified")
                return

            self.log_info(f"Processing {len(ip_list)} IP addresses...")

            for ip_entry in ip_list:
                ip_address = ip_entry.get('ip')
                description = ip_entry.get('description', '')

                if not ip_address:
                    self.log_warning("Skipping entry - missing 'ip' field")
                    ip_skipped_count += 1
                    continue

                self.log_info(f"Processing IP: {ip_address}")

                changed, action = self.get_or_create_ip_address(ip_address, description, dry_run)

                if action == "created":
                    ip_created_count += 1
                elif action == "updated":
                    ip_updated_count += 1
                elif action == "skipped":
                    ip_skipped_count += 1
                else:
                    ip_error_count += 1

        # Sync prefixes if enabled
        if enable_prefix_sync:
            prefix_json_file_name = data.get('prefix_json_file_name')

            if prefix_json_file_name:
                # Load JSON data from datasource
                self.log_info(f"Loading prefixes from datasource '{datasource_name}', file '{prefix_json_file_name}'...")
                try:
                    prefix_list = self.load_prefixes(datasource_name, prefix_json_file_name)
                    self.log_success(f"Loaded {len(prefix_list)} prefix entries")
                except Exception as e:
                    self.log_failure(f"Failed to load prefixes from datasource: {e}")
                    prefix_error_count = 1
                    return
            else:
                self.log_warning("Prefix sync enabled but filename not specified")
                return

            self.log_info(f"Processing {len(prefix_list)} prefixes...")

            for prefix_entry in prefix_list:
                prefix_value = prefix_entry.get('prefix')
                description = prefix_entry.get('description', '')
                role = prefix_entry.get('role', '')

                if not prefix_value:
                    self.log_warning("Skipping entry - missing 'prefix' field")
                    prefix_skipped_count += 1
                    continue

                self.log_info(f"Processing prefix: {prefix_value}")

                changed, action = self.get_or_create_prefix(prefix_value, description, role, dry_run)

                if action == "created":
                    prefix_created_count += 1
                elif action == "updated":
                    prefix_updated_count += 1
                elif action == "skipped":
                    prefix_skipped_count += 1
                else:
                    prefix_error_count += 1

        # Summary
        self.log_success("Sync completed!")
        self.log_success(f"IP Addresses - Created: {ip_created_count}, Updated: {ip_updated_count}, Skipped: {ip_skipped_count}, Errors: {ip_error_count}")
        self.log_success(f"Prefixes - Created: {prefix_created_count}, Updated: {prefix_updated_count}, Skipped: {prefix_skipped_count}, Errors: {prefix_error_count}")

        if dry_run:
            self.log_info("This was a dry run - no changes were saved.")


# Register the script for NetBox
script = NetBoxIPSync
