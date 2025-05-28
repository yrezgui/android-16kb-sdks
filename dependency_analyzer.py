# dependency_analyzer.py
"""
This script analyzes Maven project dependencies to identify native shared object (.so) files
and checks their ELF alignment for 16KB page size compatibility.
It recursively downloads dependencies, extracts .so files (using file magic numbers, not just extensions),
checks their alignment using objdump, and generates a JSON report.

The script now automatically uses a predefined regex to identify dependencies
that should be sourced from Google Maven (e.g., 'com.google.android.*', 'androidx.*').
All other dependencies (and their transitives if not otherwise matched) default to Maven Central.

Example Usage:

# For a Maven project (using pom.xml):
python dependency_analyzer.py path/to/your/project/pom.xml path/to/output_report.json

# For a single Maven dependency:
python dependency_analyzer.py "com.github.barteksc:pdfium-android:1.9.0" path/to/output_report.json

# Specifying a custom download directory for dependencies:
python dependency_analyzer.py path/to/your/project/pom.xml path/to/output_report.json --download-dir path/to/your/custom/download_folder
python dependency_analyzer.py "com.github.barteksc:pdfium-android:1.9.0" path/to/output_report.json --download-dir path/to/your/custom/download_folder
"""

import argparse
import json
import logging
import re
import requests
import subprocess
import zipfile
import os
import tempfile
import xml.etree.ElementTree as ET
import magic
import yaml
import sys
from packaging.version import parse as parse_version # For robust version sorting

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Hardcoded regex for Google Maven dependencies
GOOGLE_MAVEN_DEFAULT_REGEX = "(com\\.google\\.android\\..*|androidx\\..*|com\\.android\\..*|android\\.arch\\..*)"

FAILED_DOWNLOADS_FILE = "failed_downloads.txt"

def log_failed_download(gav_string):
    """Appends a GAV string for a failed download to a text file."""
    try:
        with open(FAILED_DOWNLOADS_FILE, 'a') as f:
            f.write(gav_string + '\n')
        logging.info(f"Logged failed download for {gav_string} to {FAILED_DOWNLOADS_FILE}")
    except IOError as e:
        logging.error(f"Could not write to {FAILED_DOWNLOADS_FILE}: {e}")

def parse_maven_file(file_path):
    """Parses a Maven POM file to extract dependencies."""
    logging.info(f"Parsing Maven file: {file_path}")
    dependencies = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''
        for dependency_node in root.findall(f".//{namespace}dependency"):
            group_id_element = dependency_node.find(f"{namespace}groupId")
            artifact_id_element = dependency_node.find(f"{namespace}artifactId")
            version_element = dependency_node.find(f"{namespace}version")
            group_id = group_id_element.text if group_id_element is not None else None
            artifact_id = artifact_id_element.text if artifact_id_element is not None else None
            version = version_element.text if version_element is not None else None
            if group_id and artifact_id:
                dependencies.append({"groupId": group_id, "artifactId": artifact_id, "version": version})
            else:
                logging.warning(f"Skipping dependency with missing groupId or artifactId in {file_path}")
    except ET.ParseError:
        logging.error(f"Error parsing XML file: {file_path}", exc_info=True)
        return []
    except Exception:
        logging.error(f"An unexpected error occurred while parsing {file_path}", exc_info=True)
        return []
    return dependencies

def main():
    parser = argparse.ArgumentParser(description="Analyze Maven project dependencies for .so file alignment.")
    parser.add_argument("input_source", help="Path to the Maven pom.xml file OR a direct dependency string (e.g., group:artifact:version).")
    parser.add_argument("output_report_path", help="Path to save the JSON report (directory or full path).")
    parser.add_argument("--download-dir", action="store", default=None, help="Optional. Path to a directory where dependencies will be downloaded. If provided, downloaded files will be kept.")
    args = parser.parse_args()

    initial_dependencies_list = []

    if os.path.isfile(args.input_source) and args.input_source.lower().endswith("pom.xml"):
        logging.info(f"Input source identified as POM file: {args.input_source}")
        initial_dependencies_list = parse_maven_file(args.input_source)
        if not isinstance(initial_dependencies_list, list):
            initial_dependencies_list = []
    elif ':' in args.input_source: # Basic check for GAV string
        gav_parts = args.input_source.split(':')
        if len(gav_parts) == 3:
            group_id, artifact_id, version = gav_parts[0], gav_parts[1], gav_parts[2]
            if group_id and artifact_id and version:
                logging.info(f"Input source identified as direct dependency string: {args.input_source}")
                initial_dependencies_list = [{"groupId": group_id, "artifactId": artifact_id, "version": version}]
            else:
                logging.error(f"Invalid GAV string format: '{args.input_source}'. Expected 'groupId:artifactId:version' with non-empty parts.")
                sys.exit(1)
        else:
            logging.error(f"Invalid GAV string format: '{args.input_source}'. Expected 'groupId:artifactId:version'.")
            sys.exit(1)
    else:
        logging.error(f"Unsupported input source: '{args.input_source}'. Please provide a path to a 'pom.xml' file or a GAV string like 'groupId:artifactId:version'.")
        sys.exit(1)

    logging.info(f"Initial dependencies to process: {json.dumps(initial_dependencies_list, indent=4)}")

    output_json_final_path = args.output_report_path
    if initial_dependencies_list:
        first_dep = initial_dependencies_list[0]
        group = first_dep.get('groupId')
        artifact = first_dep.get('artifactId')
        if group and artifact:
            sanitized_group = group.replace('.', '_').replace(':', '_')
            sanitized_artifact = artifact.replace('.', '_').replace(':', '_')
            dynamic_filename = f"{sanitized_group}_{sanitized_artifact}.json"
            if os.path.isdir(args.output_report_path) or not args.output_report_path.lower().endswith(".json"):
                output_dir = args.output_report_path
            else:
                output_dir = os.path.dirname(args.output_report_path)
                if not output_dir:
                    output_dir = "."
            output_json_final_path = os.path.join(output_dir, dynamic_filename)
            logging.info(f"Dynamic report filename generated: {output_json_final_path}")
        else:
            logging.warning("First dependency missing groupId or artifactId, using provided output path as is.")
    else:
        logging.info("No initial dependencies found or parsed. Report might be empty or not generated if path is a directory.")
        if os.path.isdir(output_json_final_path):
            logging.warning(f"Output path {output_json_final_path} is a directory and no dependencies were found. No report file will be created by default naming logic.")
            logging.info("No report will be generated as no dependencies were processed and output path is a directory.")
            sys.exit(0)


    output_directory = os.path.dirname(output_json_final_path)
    if output_directory:
        os.makedirs(output_directory, exist_ok=True)

    if args.download_dir:
        temp_download_dir = args.download_dir
        os.makedirs(temp_download_dir, exist_ok=True)
        logging.info(f"Using specified download directory: {temp_download_dir}")
    else:
        temp_download_dir = tempfile.mkdtemp()
        logging.info(f"Created temporary directory for downloads: {temp_download_dir}")

    so_extract_dir = os.path.join(temp_download_dir, "extracted_so_files")
    os.makedirs(so_extract_dir, exist_ok=True)
    logging.info(f"Created directory for extracted .so files: {so_extract_dir}")
    processed_gav_strings = set()
    dependency_analysis_map = {}
    all_extracted_so_data_for_json_report = []
    try:
        use_structured_paths = bool(args.download_dir)
        download_and_extract_dependencies_recursively(
            initial_dependencies=initial_dependencies_list,
            temp_dir=temp_download_dir,
            so_extract_dir=so_extract_dir,
            google_maven_regex_str=GOOGLE_MAVEN_DEFAULT_REGEX, # Use hardcoded regex
            processed_gav_strings=processed_gav_strings,
            dependency_analysis_map=dependency_analysis_map,
            all_extracted_so_data_for_json_report=all_extracted_so_data_for_json_report,
            use_structured_download_paths=use_structured_paths # New argument
        )
        logging.info(f"Total .so files extracted (for JSON flat list): {len(all_extracted_so_data_for_json_report)}")
    finally:
        if not args.download_dir:
            logging.info(f"Cleaning up temporary directory: {temp_download_dir}")
            for root_path, dirs, files_in_dir in os.walk(temp_download_dir, topdown=False):
                for name in files_in_dir:
                    try: os.remove(os.path.join(root_path, name))
                    except OSError as e: logging.error(f"Error removing file {os.path.join(root_path, name)}: {e}")
                for name in dirs:
                    try: os.rmdir(os.path.join(root_path, name))
                    except OSError as e: logging.error(f"Error removing directory {os.path.join(root_path, name)}: {e}")
            try: os.rmdir(temp_download_dir)
            except OSError as e: logging.error(f"Error removing temporary directory {temp_download_dir}: {e}")
        else:
            logging.info(f"Skipping cleanup of user-specified download directory: {temp_download_dir}")

    json_so_files_analysis_list = []
    aligned_so_files_count = 0
    unaligned_so_files_count = 0
    error_alignment_check_count = 0
    for gav_string, dep_data_entry in dependency_analysis_map.items():
        for so_file_info in dep_data_entry.get('direct_so_files', []):
            alignment_result = check_elf_alignment(so_file_info['so_file_path'])
            so_file_info.update(alignment_result)
            json_so_files_analysis_list.append(so_file_info.copy())
            if so_file_info.get('is_aligned'): aligned_so_files_count += 1
            elif so_file_info.get('error_message') or so_file_info.get('alignment_bytes') is None: error_alignment_check_count += 1
            else: unaligned_so_files_count += 1
        dep_data_entry['direct_16kb_compatibility'] = calculate_direct_compatibility(dep_data_entry)
        logging.debug(f"Direct compatibility for {gav_string}: {dep_data_entry['direct_16kb_compatibility']}")

    for gav_string in dependency_analysis_map.keys():
        calculate_indirect_compatibility(gav_string, dependency_analysis_map)
        logging.debug(f"Indirect compatibility for {gav_string}: {dependency_analysis_map[gav_string]['indirect_16kb_compatibility']}")

    logging.info(
        f"ELF alignment, direct and indirect compatibility checks complete. Total .so files processed: {len(json_so_files_analysis_list)}, "
        f"Aligned: {aligned_so_files_count}, Unaligned: {unaligned_so_files_count}, "
        f"Errors/Undetermined: {error_alignment_check_count}"
    )
    json_resolved_artifacts_list = []
    for gav_string, data in dependency_analysis_map.items():
        json_resolved_artifacts_list.append({"groupId": data['group'], "artifactId": data['artifact'], "version": data['version']})
    report_summary = {
        "total_initial_dependencies": len(initial_dependencies_list),
        "total_resolved_artifacts": len(dependency_analysis_map),
        "total_so_files_found": len(json_so_files_analysis_list),
        "aligned_so_files_count": aligned_so_files_count,
        "unaligned_so_files_count": unaligned_so_files_count,
        "error_alignment_check_count": error_alignment_check_count
    }
    final_report_data = {
        "summary": report_summary,
        "initial_dependencies": initial_dependencies_list,
        "resolved_artifacts": json_resolved_artifacts_list,
        "so_files_analysis": json_so_files_analysis_list
    }
    with open(output_json_final_path, 'w') as f:
        json.dump(final_report_data, f, indent=4, default=str)
    logging.info(f"Report saved to {output_json_final_path}")

    if dependency_analysis_map:
        generate_yaml_reports(dependency_analysis_map)
    else:
        logging.info("Skipping YAML report generation as no dependencies were processed.")


def sort_versions(version_data_list):
    """Sorts a list of version data dictionaries by their 'version' string using packaging.version."""
    return sorted(version_data_list, key=lambda x: parse_version(x['version']))

def generate_yaml_reports(dependency_analysis_map):
    """Generates YAML reports for each G:A, with versions sorted."""
    logging.info("Generating YAML reports...")
    ga_to_versions_map = {}
    # First, populate ga_to_versions_map with basic version info needed for sorting and G:A level data retrieval
    for gav_string, data in dependency_analysis_map.items():
        ga_tuple = (data['group'], data['artifact'])
        if ga_tuple not in ga_to_versions_map:
            ga_to_versions_map[ga_tuple] = []
        # Store enough info to retrieve the full data later, and for sorting
        ga_to_versions_map[ga_tuple].append({
            'version': data['version'],
            # direct_16kb_compatibility and indirect_16kb_compatibility will be fetched from the full_version_data later
        })

    for (group, artifact), version_data_list_from_run_minimal in ga_to_versions_map.items():
        if not version_data_list_from_run_minimal:
            logging.warning(f"No version data found for G:A {group}:{artifact} during YAML generation. Skipping.")
            continue

        # Determine YAML file path
        group_path_elements = group.split('.')
        sanitized_artifact_filename = artifact.replace(':', '_') + ".yml"
        yaml_file_path_elements = ['_data'] + group_path_elements + [sanitized_artifact_filename]
        yaml_file_path = os.path.join(*yaml_file_path_elements)
        
        # Prepare G:A level data from current run
        # Fetch using the first version from the minimal list to access dependency_analysis_map
        first_version_str_for_ga_info = version_data_list_from_run_minimal[0]['version']
        ga_level_gav_for_info = f"{group}:{artifact}:{first_version_str_for_ga_info}"
        ga_level_data_from_run = dependency_analysis_map.get(ga_level_gav_for_info)

        if not ga_level_data_from_run:
            logging.error(f"Could not retrieve G:A level data for {ga_level_gav_for_info} from current run. Skipping YAML for this G:A.")
            continue
            
        dependency_id_current = f"{group}:{artifact}"
        group_id_current = group
        artifact_id_current = artifact
        project_url_current = ga_level_data_from_run.get('project_url')
        maven_repo_name_raw_current = ga_level_data_from_run.get('maven_repository_name')
        
        maven_repository_current = "Other" # Default
        if maven_repo_name_raw_current == "Google Maven":
            maven_repository_current = "Google"
        elif maven_repo_name_raw_current == "Maven Central":
            maven_repository_current = "maven-central"
        elif maven_repo_name_raw_current:
            maven_repository_current = maven_repo_name_raw_current

        # Prepare versions_current_run_list (fully populated and sorted)
        versions_current_run_list = []
        # Sort the minimal list first to process in order, though final sort happens after merge
        sorted_versions_minimal_from_run = sort_versions(version_data_list_from_run_minimal)

        for version_info_minimal in sorted_versions_minimal_from_run:
            current_version_str = version_info_minimal['version']
            gav_string_current_run = f"{group}:{artifact}:{current_version_str}"
            full_version_data_current_run = dependency_analysis_map.get(gav_string_current_run)

            if not full_version_data_current_run:
                logging.warning(f"Missing full data for {gav_string_current_run} in dependency_analysis_map (current run). Skipping this version in YAML.")
                continue

            self_contains_native_code = bool(full_version_data_current_run.get('direct_so_files'))
            transitive_contains_native_code = False
            trans_deps_gavs = full_version_data_current_run.get('transitive_dependencies', [])
            for trans_gav in trans_deps_gavs:
                trans_dep_data = dependency_analysis_map.get(trans_gav)
                if trans_dep_data and trans_dep_data.get('direct_so_files'):
                    transitive_contains_native_code = True
                    break
            
            version_yaml_entry_current_run = {
                'version': current_version_str,
                'self_contains_native_code': self_contains_native_code,
                'self_16kb_compatibility': full_version_data_current_run.get('direct_16kb_compatibility'),
                'transitive_contains_native_code': transitive_contains_native_code,
                'transitive_16kb_compatibility': full_version_data_current_run.get('indirect_16kb_compatibility')
            }
            versions_current_run_list.append(version_yaml_entry_current_run)
        # versions_current_run_list is already sorted by version due to sorted_versions_minimal_from_run

        final_yaml_data_to_dump = {}
        log_action_verb = "Generated" # Default to "Generated" for new files

        if os.path.exists(yaml_file_path):
            logging.info(f"File {yaml_file_path} exists. Attempting merge.")
            existing_yaml_data = None
            try:
                with open(yaml_file_path, 'r') as f:
                    existing_yaml_data = yaml.safe_load(f)
                if not isinstance(existing_yaml_data, dict): # Handle empty or malformed file
                    logging.warning(f"Existing YAML file {yaml_file_path} is malformed or empty. Treating as new file.")
                    existing_yaml_data = None # Reset to ensure it's treated as a new file scenario
            except yaml.YAMLError as e_yaml:
                logging.warning(f"Error loading existing YAML file {yaml_file_path}: {e_yaml}. Treating as new file.")
                existing_yaml_data = None # Reset
            except FileNotFoundError: # Should not happen due to os.path.exists, but good practice
                logging.warning(f"Existing YAML file {yaml_file_path} not found despite os.path.exists. Treating as new file.")
                existing_yaml_data = None # Reset
            
            if existing_yaml_data:
                # Update top-level fields
                existing_yaml_data['dependency_id'] = dependency_id_current
                existing_yaml_data['group_id'] = group_id_current
                existing_yaml_data['artifact_id'] = artifact_id_current
                existing_yaml_data['project_url'] = project_url_current
                existing_yaml_data['maven_repository'] = maven_repository_current

                # Merge versions
                existing_versions_list = existing_yaml_data.get('versions', [])
                if not isinstance(existing_versions_list, list): # Ensure it's a list
                    logging.warning(f"Versions in existing YAML {yaml_file_path} is not a list. Overwriting with current run's versions.")
                    existing_versions_list = []
                
                existing_versions_map = {v['version']: v for v in existing_versions_list}

                for version_entry_current_run in versions_current_run_list:
                    version_str_current = version_entry_current_run['version']
                    if version_str_current in existing_versions_map:
                        # Update existing version entry
                        existing_versions_map[version_str_current].update(version_entry_current_run)
                    else:
                        # Add new version entry
                        existing_versions_list.append(version_entry_current_run)
                
                existing_yaml_data['versions'] = sort_versions(existing_versions_list)
                final_yaml_data_to_dump = existing_yaml_data
                log_action_verb = "Updated"
            else: # Existing file was unreadable or malformed
                logging.info(f"File {yaml_file_path} was unreadable or malformed. Creating new file.")
                # Fall through to "else" block logic by not setting final_yaml_data_to_dump here
                pass # Explicitly do nothing to fall through

        # This block handles both "file does not exist" and "file existed but was unreadable/malformed"
        if not final_yaml_data_to_dump: # If it's still empty (new file or error loading existing)
            logging.info(f"File {yaml_file_path} does not exist or was unreadable. Creating new file.")
            final_yaml_data_to_dump = {
                'dependency_id': dependency_id_current,
                'group_id': group_id_current,
                'artifact_id': artifact_id_current,
                'project_url': project_url_current,
                'maven_repository': maven_repository_current,
                'versions': versions_current_run_list # Already sorted
            }
            log_action_verb = "Created"

        try:
            yaml_output_dir = os.path.dirname(yaml_file_path)
            os.makedirs(yaml_output_dir, exist_ok=True)
            with open(yaml_file_path, 'w') as f:
                yaml.dump(final_yaml_data_to_dump, f, sort_keys=False, default_flow_style=False, indent=2)
            logging.info(f"{log_action_verb} YAML report: {yaml_file_path}")
        except Exception as e:
            logging.error(f"Error writing YAML report {yaml_file_path}: {e}", exc_info=True)


def calculate_direct_compatibility(gav_entry):
    direct_so_files = gav_entry.get('direct_so_files', [])
    if not direct_so_files: return True
    for so_file_info in direct_so_files:
        if not so_file_info.get('is_aligned', False): return False
    return True

def calculate_indirect_compatibility(gav_key, dependency_analysis_map):
    gav_entry = dependency_analysis_map.get(gav_key)
    if not gav_entry:
        logging.error(f"GAV key {gav_key} not found in dependency_analysis_map during indirect calculation.")
        return False
    if 'indirect_16kb_compatibility' in gav_entry and gav_entry['indirect_16kb_compatibility'] is not None:
        return gav_entry['indirect_16kb_compatibility']

    if gav_entry.get('direct_16kb_compatibility') is False:
        gav_entry['indirect_16kb_compatibility'] = False
        return False

    transitive_dependencies = gav_entry.get('transitive_dependencies', [])
    if not transitive_dependencies:
        gav_entry['indirect_16kb_compatibility'] = gav_entry.get('direct_16kb_compatibility', True)
        return gav_entry['indirect_16kb_compatibility']

    overall_indirect_status = True
    for child_gav_key in transitive_dependencies:
        child_gav_entry = dependency_analysis_map.get(child_gav_key)
        if not child_gav_entry:
            logging.warning(f"Child GAV {child_gav_key} (transitive of {gav_key}) not found in map for indirect calc. Assuming non-compatible for safety.")
            overall_indirect_status = False
            break
        
        if not calculate_indirect_compatibility(child_gav_key, dependency_analysis_map):
            overall_indirect_status = False
            break
            
    gav_entry['indirect_16kb_compatibility'] = overall_indirect_status
    return overall_indirect_status

def extract_so_files_from_archive(artifact_path, so_extract_dir, dependency_info):
    extracted_files_metadata = []
    ELF_MIME_TYPES = {'application/x-sharedlib', 'application/x-elf'}
    try:
        with zipfile.ZipFile(artifact_path, 'r') as archive:
            for member_info in archive.infolist():
                if member_info.is_dir(): continue
                try:
                    file_buffer = archive.read(member_info.filename)[:2048]
                    if not file_buffer: continue
                    mime_type = magic.from_buffer(file_buffer, mime=True)
                except Exception as e:
                    logging.warning(f"Could not determine MIME type for {member_info.filename} in {artifact_path} using python-magic: {e}. Falling back to extension check for .so files.")
                    if not member_info.filename.endswith(".so"): continue
                    mime_type = 'application/x-sharedlib'

                if mime_type in ELF_MIME_TYPES:
                    original_filename_from_archive = os.path.basename(member_info.filename)

                    if not original_filename_from_archive.endswith(".so") and mime_type == 'application/x-sharedlib':
                        logging.info(f"File '{original_filename_from_archive}' in {artifact_path} identified as ELF shared library by magic, but does not have .so extension.")
                    elif mime_type == 'application/x-elf':
                         logging.info(f"File '{original_filename_from_archive}' in {artifact_path} identified as a generic ELF file by magic (MIME: {mime_type}). Treating as .so for analysis.")

                    base_unique_filename = (f"{dependency_info['groupId']}_{dependency_info['artifactId']}_{dependency_info['version']}_{original_filename_from_archive}").replace(':', '_').replace('-', '_').replace('/', '_')
                    if not base_unique_filename.endswith(".so"):
                        unique_so_filename = f"{base_unique_filename}.so"
                    else:
                        unique_so_filename = base_unique_filename

                    target_so_path = os.path.join(so_extract_dir, unique_so_filename)
                    try:
                        with archive.open(member_info.filename) as source, open(target_so_path, 'wb') as target:
                            target.write(source.read())
                        logging.info(f"Extracted ELF file: '{original_filename_from_archive}' to '{target_so_path}' from {dependency_info['artifactId']}")
                        extracted_files_metadata.append({
                            "so_file_path": target_so_path,
                            "original_so_filename": original_filename_from_archive,
                            "dependency_group": dependency_info['groupId'],
                            "dependency_artifact": dependency_info['artifactId'],
                            "dependency_version": dependency_info['version'],
                            "mime_type_detected": mime_type
                        })
                    except Exception as e_extract:
                        logging.error(f"Error extracting {member_info.filename} to {target_so_path}: {e_extract}", exc_info=True)
    except zipfile.BadZipFile:
        logging.error(f"Bad ZIP file: {artifact_path}", exc_info=True)
    except Exception as e_zip:
        logging.error(f"Error processing archive {artifact_path}: {e_zip}", exc_info=True)
    return extracted_files_metadata

def check_elf_alignment(so_file_path):
    cmd = ["objdump", "-p", so_file_path]
    result = {'alignment_value_str': None, 'alignment_bytes': None, 'is_aligned': False, 'error_message': None}
    min_alignment_bytes = 16384
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            result['error_message'] = f"objdump failed with return code {proc.returncode}. Stderr: {proc.stderr.strip()}"
            logging.error(f"objdump error for {so_file_path}: {result['error_message']}")
            return result

        output = proc.stdout
        load_lines = [line for line in output.splitlines() if "LOAD" in line and "align" in line]

        if not load_lines:
            result['error_message'] = "No LOAD segments with alignment info found in objdump output."
            logging.warning(f"{result['error_message']} for {so_file_path}")
            return result

        first_load_line = load_lines[0]
        match_align = re.search(r'align\s+(0x[0-9a-fA-F]+|\d+|2\*\*\d+)', first_load_line)

        if not match_align:
            result['error_message'] = "Could not parse alignment from the first LOAD segment."
            logging.warning(f"{result['error_message']} Line: {first_load_line} for {so_file_path}")
            return result

        alignment_str = match_align.group(1).strip()
        result['alignment_value_str'] = alignment_str
        alignment_bytes = None

        if alignment_str.startswith("2**"):
            try:
                exponent = int(alignment_str.split("**")[1])
                alignment_bytes = 2 ** exponent
            except ValueError:
                result['error_message'] = f"Invalid format for 2**N alignment: {alignment_str}"
                logging.warning(result['error_message'])
        elif alignment_str.startswith("0x"):
            try:
                alignment_bytes = int(alignment_str, 16)
            except ValueError:
                result['error_message'] = f"Invalid hex format for alignment: {alignment_str}"
                logging.warning(result['error_message'])
        else:
            try:
                alignment_bytes = int(alignment_str)
            except ValueError:
                result['error_message'] = f"Unknown or invalid decimal alignment format: {alignment_str}"
                logging.warning(result['error_message'])

        if alignment_bytes is not None:
            result['alignment_bytes'] = alignment_bytes
            if alignment_bytes >= min_alignment_bytes and (alignment_bytes % min_alignment_bytes == 0 or min_alignment_bytes % alignment_bytes == 0) :
                 result['is_aligned'] = True
            logging.info(f"File: {os.path.basename(so_file_path)}, Align String: '{alignment_str}', Bytes: {alignment_bytes}, Aligned for {min_alignment_bytes}B: {result['is_aligned']}")
        else:
            if not result['error_message']:
                 logging.warning(f"Could not determine alignment in bytes for {so_file_path} from string '{alignment_str}'")


    except FileNotFoundError:
        result['error_message'] = "objdump command not found. Please ensure binutils (objdump) is installed and in your PATH."
        logging.error(result['error_message'])
    except Exception as e:
        result['error_message'] = f"An unexpected error occurred during alignment check: {str(e)}"
        logging.error(f"{result['error_message']} for {so_file_path}", exc_info=True)
    return result

def download_and_extract_dependencies_recursively(
    initial_dependencies, temp_dir, so_extract_dir, google_maven_regex_str,
    processed_gav_strings, dependency_analysis_map, all_extracted_so_data_for_json_report,
    use_structured_download_paths: bool
):
    dependencies_to_process_queue = list(initial_dependencies)

    while dependencies_to_process_queue:
        dep_info = dependencies_to_process_queue.pop(0)

        group_id = dep_info.get("groupId")
        artifact_id = dep_info.get("artifactId")
        version = dep_info.get("version")

        if not (group_id and artifact_id and version):
            logging.warning(f"Skipping dependency with missing GAV components: {dep_info}")
            continue

        current_gav_string = f"{group_id}:{artifact_id}:{version}"

        if current_gav_string in processed_gav_strings:
            logging.info(f"Skipping already processed dependency: {current_gav_string}")
            continue
        processed_gav_strings.add(current_gav_string)

        logging.info(f"Processing dependency: {current_gav_string}")

        if current_gav_string not in dependency_analysis_map:
            dependency_analysis_map[current_gav_string] = {
                'gav': current_gav_string, 'group': group_id, 'artifact': artifact_id, 'version': version,
                'direct_so_files': [], 'transitive_dependencies': [],
                'direct_16kb_compatibility': None, 'indirect_16kb_compatibility': None,
                'downloaded_artifact_path': None, 'pom_download_url': None, 'artifact_download_url': None,
                'project_url': None, 'maven_repository_name': None
            }
        current_dep_map_entry = dependency_analysis_map[current_gav_string]

        repo_url = get_repository_url(dep_info, google_maven_regex_str) # google_maven_regex_str is now the hardcoded one
        if "maven.google.com" in repo_url:
            current_dep_map_entry['maven_repository_name'] = "Google Maven"
        elif "repo.maven.apache.org" in repo_url:
            current_dep_map_entry['maven_repository_name'] = "Maven Central"
        else:
            current_dep_map_entry['maven_repository_name'] = repo_url

        pom_url = construct_artifact_url(dep_info, repo_url, artifact_type="pom")
        current_dep_map_entry['pom_download_url'] = pom_url

        if not pom_url:
            logging.error(f"Could not construct POM URL for {current_gav_string}. Skipping.")
            continue

        pom_filename_to_use = f"{artifact_id}-{version}.pom"
        if use_structured_download_paths:
            group_path = group_id.replace('.', os.sep)
            artifact_specific_download_dir = os.path.join(temp_dir, group_path, artifact_id, version)
            effective_pom_download_dir = artifact_specific_download_dir
        else:
            effective_pom_download_dir = temp_dir
        
        downloaded_pom_path = download_artifact(pom_url, effective_pom_download_dir, pom_filename_to_use)

        if downloaded_pom_path:
            logging.info(f"Successfully downloaded POM: {pom_filename_to_use} from {pom_url}")
            try:
                tree = ET.parse(downloaded_pom_path)
                root = tree.getroot()
                namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''

                project_url_element = root.find(f"{namespace}url") # Note: No .// for direct child
                project_url = project_url_element.text.strip() if project_url_element is not None and project_url_element.text else None
                if not project_url:
                    scm_node = root.find(f"{namespace}scm") # Note: No .// for direct child
                    if scm_node is not None:
                        scm_url_element = scm_node.find(f"{namespace}url") # Note: No .// for direct child
                        project_url = scm_url_element.text.strip() if scm_url_element is not None and scm_url_element.text else None
                current_dep_map_entry['project_url'] = project_url
                if project_url:
                    logging.info(f"Extracted project URL for {current_gav_string}: {project_url}")
                else:
                    logging.info(f"No project URL found in POM for {current_gav_string}")

            except ET.ParseError:
                logging.warning(f"Could not parse downloaded POM {downloaded_pom_path} to extract project URL.")
            except Exception as e_url_extract:
                logging.error(f"Unexpected error extracting project URL from {downloaded_pom_path}: {e_url_extract}", exc_info=True)

            transitive_deps_from_pom = parse_maven_file(downloaded_pom_path) # parse_maven_file also parses, but we need project_url before transitive
            for trans_dep_info in transitive_deps_from_pom:
                trans_g = trans_dep_info.get('groupId')
                trans_a = trans_dep_info.get('artifactId')
                trans_v = trans_dep_info.get('version')
                if trans_g and trans_a and trans_v:
                    trans_gav_string = f"{trans_g}:{trans_a}:{trans_v}"
                    current_dep_map_entry['transitive_dependencies'].append(trans_gav_string)
                    is_in_queue = any(
                        f"{d.get('groupId')}:{d.get('artifactId')}:{d.get('version')}" == trans_gav_string
                        for d in dependencies_to_process_queue
                    )
                    if trans_gav_string not in processed_gav_strings and not is_in_queue:
                        dependencies_to_process_queue.append(trans_dep_info)
                else:
                    logging.warning(f"Skipping transitive dependency with incomplete GAV: {trans_dep_info} from POM {pom_filename}")
            logging.info(f"Found {len(current_dep_map_entry['transitive_dependencies'])} transitive dependencies for {current_gav_string}")
        else:
            logging.warning(f"Failed to download POM for {current_gav_string} from {pom_url}. Transitive dependencies will not be processed for this specific artifact's POM.")
            log_failed_download(current_gav_string + " (POM)") # Log POM download failure

        artifact_type_from_pom = "jar"
        if downloaded_pom_path:
            try:
                tree = ET.parse(downloaded_pom_path)
                root = tree.getroot()
                namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''
                packaging_tag = root.find(f".//{namespace}packaging")
                if packaging_tag is not None and packaging_tag.text:
                    artifact_type_from_pom = packaging_tag.text.strip()
                    logging.info(f"Determined packaging for {current_gav_string} as '{artifact_type_from_pom}' from its POM.")
            except ET.ParseError:
                logging.warning(f"Could not parse downloaded POM {downloaded_pom_path} to determine packaging. Defaulting to 'jar'.")
            except Exception as e_parse:
                 logging.error(f"Unexpected error parsing POM {downloaded_pom_path} for packaging: {e_parse}", exc_info=True)


        artifact_type_to_download = artifact_type_from_pom
        if artifact_id.endswith("-android") or artifact_type_from_pom in ["aar", "bundle"]:
             if artifact_type_from_pom not in ["aar"] : # Avoid re-assigning if already 'aar'
                logging.info(f"Artifact {artifact_id} or packaging {artifact_type_from_pom} suggests AAR, using .aar extension.")
                artifact_type_to_download = "aar"


        main_artifact_url = construct_artifact_url(dep_info, repo_url, artifact_type=artifact_type_to_download)
        current_dep_map_entry['artifact_download_url'] = main_artifact_url

        if not main_artifact_url:
            logging.error(f"Could not construct URL for main artifact of {current_gav_string} (type: {artifact_type_to_download}). Skipping artifact download.")
            continue

        main_artifact_filename_to_use = f"{artifact_id}-{version}.{artifact_type_to_download}"
        if use_structured_download_paths:
            group_path = group_id.replace('.', os.sep) # Ensure defined, might be redundant if POM was downloaded
            artifact_specific_download_dir = os.path.join(temp_dir, group_path, artifact_id, version) # Ensure defined
            effective_artifact_download_dir = artifact_specific_download_dir
        else:
            effective_artifact_download_dir = temp_dir

        downloaded_main_artifact_path = download_artifact(main_artifact_url, effective_artifact_download_dir, main_artifact_filename_to_use)

        if downloaded_main_artifact_path:
            current_dep_map_entry['downloaded_artifact_path'] = downloaded_main_artifact_path
            logging.info(f"Successfully downloaded main artifact: {main_artifact_filename_to_use} from {main_artifact_url}")
            so_files_metadata_list = extract_so_files_from_archive(downloaded_main_artifact_path, so_extract_dir, dep_info)
            current_dep_map_entry['direct_so_files'].extend(so_files_metadata_list)
            if so_files_metadata_list:
                all_extracted_so_data_for_json_report.extend(so_files_metadata_list)
        else:
            logging.error(f"Failed to download main artifact for {current_gav_string} from {main_artifact_url}")
            # Log main artifact download failure, but only if it's not a JAR that will be attempted as fallback
            # If it IS a jar, and fails, it's the definitive failure for this GAV's artifact.
            if artifact_type_to_download == "jar":
                log_failed_download(current_gav_string + f" (ArtifactType: {artifact_type_to_download})")

            if artifact_type_to_download != "jar": # Fallback logic only if original type wasn't JAR
                logging.info(f"Attempting fallback download with .jar extension for {current_gav_string}")
                fallback_jar_url = construct_artifact_url(dep_info, repo_url, artifact_type="jar")
                current_dep_map_entry['artifact_download_url'] += f", FallbackAttemptURL: {fallback_jar_url}"
                fallback_jar_filename = f"{artifact_id}-{version}.jar"
                # effective_artifact_download_dir is already defined from the main artifact attempt
                downloaded_fallback_jar_path = download_artifact(fallback_jar_url, effective_artifact_download_dir, fallback_jar_filename)
                if downloaded_fallback_jar_path:
                    current_dep_map_entry['downloaded_artifact_path'] = downloaded_fallback_jar_path
                    logging.info(f"Successfully downloaded fallback JAR: {fallback_jar_filename} from {fallback_jar_url}")
                    so_files_metadata_list = extract_so_files_from_archive(downloaded_fallback_jar_path, so_extract_dir, dep_info)
                    current_dep_map_entry['direct_so_files'].extend(so_files_metadata_list)
                    if so_files_metadata_list:
                        all_extracted_so_data_for_json_report.extend(so_files_metadata_list)
                else:
                    logging.error(f"Fallback JAR download also failed for {current_gav_string} from {fallback_jar_url}")
                    log_failed_download(current_gav_string + " (Fallback JAR)") # Log fallback JAR download failure


def get_repository_url(dependency, google_maven_regex_str):
    dep_group_id = dependency.get("groupId", "")
    dep_artifact_id = dependency.get("artifactId", "")

    if google_maven_regex_str: # This will always be true now with a hardcoded string
        try:
            google_maven_regex = re.compile(google_maven_regex_str)
            # Check groupID or G:A string.
            # Using f-string for clarity if dep_artifact_id could be empty.
            ga_string_for_regex = f"{dep_group_id}:{dep_artifact_id}" if dep_artifact_id else dep_group_id

            if google_maven_regex.search(dep_group_id) or \
               (dep_artifact_id and google_maven_regex.search(ga_string_for_regex)): # Ensure artifact_id exists for G:A check
                logging.info(f"Using Google Maven for {dep_group_id}:{dep_artifact_id if dep_artifact_id else '*'}")
                return "https://maven.google.com/"
        except re.error as e:
            logging.warning(f"Invalid hardcoded regex for Google Maven: '{google_maven_regex_str}'. Error: {e}. Defaulting to Maven Central.")
    
    logging.info(f"Using Maven Central for {dep_group_id}:{dep_artifact_id if dep_artifact_id else '*'}")
    return "https://repo.maven.apache.org/maven2/"

def construct_artifact_url(dependency, base_repo_url, artifact_type="jar"):
    group_id = dependency.get("groupId")
    artifact_id = dependency.get("artifactId")
    version = dependency.get("version")

    if not (group_id and artifact_id and version):
        logging.warning(f"Missing GAV components in dependency: {dependency}. Cannot construct URL.")
        return None

    group_path = group_id.replace('.', '/')
    artifact_filename_base = f"{artifact_id}-{version}"
    artifact_url = f"{base_repo_url}{group_path}/{artifact_id}/{version}/{artifact_filename_base}.{artifact_type}"
    return artifact_url

def download_artifact(artifact_url, download_dir, artifact_filename):
    if not os.path.exists(download_dir):
        try:
            os.makedirs(download_dir, exist_ok=True)
        except OSError as e:
            logging.error(f"Failed to create download directory {download_dir}: {e}")
            return None

    full_download_path = os.path.join(download_dir, artifact_filename)

    try:
        logging.info(f"Attempting to download: {artifact_url} to {full_download_path}")
        response = requests.get(artifact_url, stream=True, timeout=(10, 30))
        response.raise_for_status()
        with open(full_download_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Successfully downloaded {artifact_filename}")
        return full_download_path
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error downloading {artifact_filename} from {artifact_url}: {e}")
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error downloading {artifact_filename} from {artifact_url}: {e}")
    except requests.exceptions.Timeout:
        logging.error(f"Timeout downloading {artifact_filename} from {artifact_url}")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed for {artifact_filename} from {artifact_url}: {e}")
    except IOError as e:
        logging.error(f"File IO error for {full_download_path}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred downloading {artifact_filename} from {artifact_url}: {e}", exc_info=True)
    return None


if __name__ == "__main__":
    main()