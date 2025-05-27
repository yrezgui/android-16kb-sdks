# dependency_analyzer.py
"""
This script analyzes Maven project dependencies to identify native shared object (.so) files
and checks their ELF alignment for 16KB page size compatibility.
It recursively downloads dependencies, extracts .so files (using file magic numbers, not just extensions),
checks their alignment using objdump, and generates a JSON report.

Example Usage:

# For a Maven project:
python dependency_analyzer.py path/to/your/project/pom.xml path/to/output_report.json

# For a project where specific dependencies (e.g., any under 'com.google.android' group or musically 'androidx.core:core-ktx') 
# should be sourced from Google Maven, and others from Maven Central (if they are transitive dependencies of a primary Google Maven one):
python dependency_analyzer.py path/to/pom.xml output_report.json --google-maven-regex "(com\.google\.android\..*|androidx\.core:core-ktx)"
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
    parser.add_argument("build_file_path", help="Path to the Maven pom.xml file.")
    parser.add_argument("output_report_path", help="Path to save the JSON report (directory or full path).")
    parser.add_argument(
        "--google-maven-regex", 
        help="Optional regex for identifying dependencies that should be sourced from Google Maven. "
             "All others (and their transitives if not otherwise matched) default to Maven Central."
    )
    args = parser.parse_args()
    build_file_name = os.path.basename(args.build_file_path)
    if build_file_name.lower() != "pom.xml":
        logging.error(f"Unsupported build file: '{build_file_name}'. This script currently only supports 'pom.xml' files.")
        sys.exit(1) 
    logging.info(f"Parsing Maven pom.xml file: {args.build_file_path}")
    initial_dependencies_list = parse_maven_file(args.build_file_path) 
    if not isinstance(initial_dependencies_list, list):
        initial_dependencies_list = []
    logging.info(f"Initial dependencies found: {json.dumps(initial_dependencies_list, indent=4)}")

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
        logging.info("No initial dependencies found, using provided output path as is.")

    output_directory = os.path.dirname(output_json_final_path)
    if output_directory: 
        os.makedirs(output_directory, exist_ok=True)
    
    temp_download_dir = tempfile.mkdtemp()
    logging.info(f"Created temporary directory for downloads: {temp_download_dir}")
    so_extract_dir = os.path.join(temp_download_dir, "extracted_so_files")
    os.makedirs(so_extract_dir, exist_ok=True)
    logging.info(f"Created directory for extracted .so files: {so_extract_dir}")
    processed_gav_strings = set()
    dependency_analysis_map = {}
    all_extracted_so_data_for_json_report = [] 
    try:
        download_and_extract_dependencies_recursively(
            initial_dependencies=initial_dependencies_list, 
            temp_dir=temp_download_dir,
            so_extract_dir=so_extract_dir,
            google_maven_regex_str=args.google_maven_regex,
            processed_gav_strings=processed_gav_strings, 
            dependency_analysis_map=dependency_analysis_map, 
            all_extracted_so_data_for_json_report=all_extracted_so_data_for_json_report 
        )
        logging.info(f"Total .so files extracted (for JSON flat list): {len(all_extracted_so_data_for_json_report)}")
    finally:
        logging.info(f"Cleaning up temporary directory: {temp_download_dir}")
        for root, dirs, files in os.walk(temp_download_dir, topdown=False):
            for name in files:
                try: os.remove(os.path.join(root, name))
                except OSError as e: logging.error(f"Error removing file {os.path.join(root, name)}: {e}")
            for name in dirs:
                try: os.rmdir(os.path.join(root, name))
                except OSError as e: logging.error(f"Error removing directory {os.path.join(root, name)}: {e}")
        try: os.rmdir(temp_download_dir)
        except OSError as e: logging.error(f"Error removing temporary directory {temp_download_dir}: {e}")

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

    # Generate YAML reports
    generate_yaml_reports(dependency_analysis_map)


def sort_versions(version_data_list):
    """Sorts a list of version data dictionaries by their 'version' string using packaging.version."""
    return sorted(version_data_list, key=lambda x: parse_version(x['version']))

def generate_yaml_reports(dependency_analysis_map):
    """Generates YAML reports for each G:A, with versions sorted."""
    logging.info("Generating YAML reports...")
    ga_to_versions_map = {}
    for gav_string, data in dependency_analysis_map.items():
        ga_tuple = (data['group'], data['artifact'])
        if ga_tuple not in ga_to_versions_map:
            ga_to_versions_map[ga_tuple] = []
        
        version_entry = {
            'version': data['version'],
            'direct_16kb_compatibility': data.get('direct_16kb_compatibility'),
            'indirect_16kb_compatibility': data.get('indirect_16kb_compatibility')
        }
        ga_to_versions_map[ga_tuple].append(version_entry)

    for (group, artifact), version_data_list in ga_to_versions_map.items():
        sorted_versions_data = sort_versions(version_data_list)
        
        yaml_data = {
            'artifact_id': artifact, # Per spec, artifact_id is top level under group
            'versions': sorted_versions_data
        }
        
        # Determine output path: _data/group/parts/artifact.yml
        group_path_elements = group.split('.')
        # Sanitize artifact name for filename, replacing ':' which is common in Maven artifact IDs if not already handled
        sanitized_artifact_filename = artifact.replace(':', '_') + ".yml" 
        yaml_file_path_elements = ['_data'] + group_path_elements + [sanitized_artifact_filename]
        yaml_file_path = os.path.join(*yaml_file_path_elements)
        
        try:
            yaml_output_dir = os.path.dirname(yaml_file_path)
            os.makedirs(yaml_output_dir, exist_ok=True)
            with open(yaml_file_path, 'w') as f:
                yaml.dump(yaml_data, f, sort_keys=False, default_flow_style=False, indent=2)
            logging.info(f"Generated YAML report: {yaml_file_path}")
        except Exception as e:
            logging.error(f"Error generating YAML report {yaml_file_path}: {e}", exc_info=True)


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
    if gav_entry['indirect_16kb_compatibility'] is not None:
        return gav_entry['indirect_16kb_compatibility']
    transitive_dependencies = gav_entry.get('transitive_dependencies', [])
    if not transitive_dependencies:
        gav_entry['indirect_16kb_compatibility'] = True 
        return True
    overall_indirect_status = True
    for child_gav_key in transitive_dependencies:
        child_gav_entry = dependency_analysis_map.get(child_gav_key)
        if not child_gav_entry:
            logging.warning(f"Child GAV {child_gav_key} (transitive of {gav_key}) not found in map for indirect calc. Assuming non-compatible.")
            overall_indirect_status = False
            break 
        if child_gav_entry['direct_16kb_compatibility'] is False: 
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
                    logging.warning(f"Could not determine MIME type for {member_info.filename} in {artifact_path} using python-magic: {e}")
                    if not member_info.filename.endswith(".so"): continue 
                    mime_type = 'application/x-sharedlib' 
                if mime_type in ELF_MIME_TYPES:
                    original_filename_from_archive = os.path.basename(member_info.filename)
                    if not original_filename_from_archive.endswith(".so") and mime_type == 'application/x-sharedlib':
                        logging.info(f"File '{original_filename_from_archive}' in {artifact_path} identified as ELF shared library by magic, but does not have .so extension.")
                    elif mime_type == 'application/x-elf':
                         logging.info(f"File '{original_filename_from_archive}' in {artifact_path} identified as a generic ELF file by magic (MIME: {mime_type}).")
                    base_unique_filename = (f"{dependency_info['groupId']}_{dependency_info['artifactId']}_{dependency_info['version']}_{original_filename_from_archive}").replace(':', '_').replace('-', '_').replace('/', '_') 
                    if not base_unique_filename.endswith(".so"): unique_so_filename = f"{base_unique_filename}.so"
                    else: unique_so_filename = base_unique_filename
                    target_so_path = os.path.join(so_extract_dir, unique_so_filename)
                    try:
                        with archive.open(member_info.filename) as source, open(target_so_path, 'wb') as target: target.write(source.read())
                        logging.info(f"Extracted ELF file: '{original_filename_from_archive}' to '{target_so_path}' from {dependency_info['artifactId']}")
                        extracted_files_metadata.append({"so_file_path": target_so_path, "original_so_filename": original_filename_from_archive, "dependency_group": dependency_info['groupId'], "dependency_artifact": dependency_info['artifactId'], "dependency_version": dependency_info['version'], "mime_type_detected": mime_type})
                    except Exception as e_extract: logging.error(f"Error extracting {member_info.filename} to {target_so_path}: {e_extract}", exc_info=True)
    except zipfile.BadZipFile: logging.error(f"Bad ZIP file: {artifact_path}", exc_info=True)
    except Exception as e_zip: logging.error(f"Error processing archive {artifact_path}: {e_zip}", exc_info=True)
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
            result['error_message'] = "No LOAD segments found in objdump output."
            logging.warning(f"{result['error_message']} for {so_file_path}")
            return result
        first_load_line = load_lines[0]
        match_align = re.search(r'align\s+(.*)', first_load_line)
        if not match_align:
            result['error_message'] = "Could not parse alignment from LOAD segment."
            logging.warning(f"{result['error_message']} Line: {first_load_line}")
            return result
        alignment_str = match_align.group(1).strip()
        result['alignment_value_str'] = alignment_str
        alignment_bytes = None
        if alignment_str.startswith("2**"):
            try: exponent = int(alignment_str.split("**")[1]); alignment_bytes = 2 ** exponent
            except ValueError: result['error_message'] = f"Invalid format for 2**N alignment: {alignment_str}"; logging.warning(result['error_message'])
        elif alignment_str.startswith("0x"):
            try: alignment_bytes = int(alignment_str, 16)
            except ValueError: result['error_message'] = f"Invalid hex format for alignment: {alignment_str}"; logging.warning(result['error_message'])
        else:
            try: alignment_bytes = int(alignment_str)
            except ValueError: result['error_message'] = f"Unknown alignment format: {alignment_str}"; logging.warning(result['error_message'])
        if alignment_bytes is not None:
            result['alignment_bytes'] = alignment_bytes
            if alignment_bytes >= min_alignment_bytes: result['is_aligned'] = True
            logging.info(f"File: {so_file_path}, Align String: '{alignment_str}', Bytes: {alignment_bytes}, Aligned: {result['is_aligned']}")
        else: logging.warning(f"Could not determine alignment in bytes for {so_file_path} from string '{alignment_str}'")
    except FileNotFoundError:
        result['error_message'] = "objdump command not found. Please ensure binutils is installed."
        logging.error(result['error_message'])
    except Exception as e:
        result['error_message'] = f"An unexpected error occurred during alignment check: {str(e)}"
        logging.error(f"{result['error_message']} for {so_file_path}", exc_info=True)
    return result

def download_and_extract_dependencies_recursively(
    initial_dependencies, temp_dir, so_extract_dir, google_maven_regex_str,
    processed_gav_strings, dependency_analysis_map, all_extracted_so_data_for_json_report 
):
    dependencies_to_process_queue = list(initial_dependencies) 
    while dependencies_to_process_queue:
        dep_info = dependencies_to_process_queue.pop(0) 
        group_id = dep_info.get("groupId")
        artifact_id = dep_info.get("artifactId")
        version = dep_info.get("version")
        if not group_id or not artifact_id or not version:
            logging.warning(f"Skipping dependency with missing GAV: {dep_info}")
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
                'downloaded_artifact_path': None 
            }
        current_dep_map_entry = dependency_analysis_map[current_gav_string]
        repo_url = get_repository_url(dep_info, google_maven_regex_str)
        pom_url = construct_artifact_url(dep_info, repo_url, artifact_type="pom")
        pom_filename = f"{artifact_id}-{version}.pom" 
        downloaded_pom_path = download_artifact(pom_url, temp_dir, pom_filename)
        if downloaded_pom_path:
            logging.info(f"Successfully downloaded POM: {pom_filename} from {pom_url}")
            transitive_deps_from_pom = parse_maven_file(downloaded_pom_path)
            for trans_dep_info in transitive_deps_from_pom:
                trans_gav_string = f"{trans_dep_info.get('groupId')}:{trans_dep_info.get('artifactId')}:{trans_dep_info.get('version')}"
                if trans_dep_info.get('groupId') and trans_dep_info.get('artifactId') and trans_dep_info.get('version'):
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
            logging.warning(f"Failed to download POM for {current_gav_string} from {pom_url}. Transitive dependencies will not be processed for this path.")
        artifact_type = "jar" 
        if downloaded_pom_path: 
            try:
                tree = ET.parse(downloaded_pom_path)
                root = tree.getroot()
                namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''
                packaging_tag = root.find(f".//{namespace}packaging")
                if packaging_tag is not None and packaging_tag.text:
                    artifact_type = packaging_tag.text
                    logging.info(f"Determined packaging for {current_gav_string} as '{artifact_type}' from its POM.")
            except ET.ParseError:
                logging.warning(f"Could not parse downloaded POM {downloaded_pom_path} to determine packaging. Defaulting to 'jar'.")
        main_artifact_url = construct_artifact_url(dep_info, repo_url, artifact_type=artifact_type)
        if not main_artifact_url:
            logging.error(f"Could not construct URL for main artifact of {current_gav_string}")
            continue
        main_artifact_filename = f"{artifact_id}-{version}.{artifact_type}"
        downloaded_main_artifact_path = download_artifact(main_artifact_url, temp_dir, main_artifact_filename)
        if downloaded_main_artifact_path:
            current_dep_map_entry['downloaded_artifact_path'] = downloaded_main_artifact_path
            logging.info(f"Successfully downloaded main artifact: {main_artifact_filename} from {main_artifact_url}")
            so_files_metadata_list = extract_so_files_from_archive(downloaded_main_artifact_path, so_extract_dir, dep_info)
            current_dep_map_entry['direct_so_files'] = so_files_metadata_list
            if so_files_metadata_list:
                all_extracted_so_data_for_json_report.extend(so_files_metadata_list)
        else:
            logging.error(f"Failed to download main artifact for {current_gav_string} from {main_artifact_url}")

def get_repository_url(dependency, google_maven_regex_str):
    if google_maven_regex_str:
        try:
            google_maven_regex = re.compile(google_maven_regex_str)
            if google_maven_regex.search(dependency.get("groupId", "")) or google_maven_regex.search(dependency.get("artifactId", "")):
                logging.info(f"Using Google Maven for {dependency['groupId']}:{dependency['artifactId']}")
                return "https://maven.google.com/"
        except re.error as e: logging.warning(f"Invalid regex provided for Google Maven: {google_maven_regex_str}. Error: {e}")
    logging.info(f"Using Maven Central for {dependency['groupId']}:{dependency['artifactId']}")
    return "https://repo.maven.apache.org/maven2/"

def construct_artifact_url(dependency, base_repo_url, artifact_type="jar"):
    group_path = dependency["groupId"].replace('.', '/')
    artifact_id = dependency["artifactId"]
    version = dependency["version"]
    if not version: 
        logging.warning(f"Version is missing for {dependency['groupId']}:{dependency['artifactId']}. Cannot construct URL.")
        return None 
    artifact_filename_base = f"{artifact_id}-{version}"
    artifact_url = f"{base_repo_url}{group_path}/{artifact_id}/{version}/{artifact_filename_base}.{artifact_type}"
    return artifact_url

def download_artifact(artifact_url, download_path, artifact_name):
    full_download_path = os.path.join(download_path, artifact_name)
    try:
        logging.info(f"Attempting to download: {artifact_url} to {full_download_path}")
        response = requests.get(artifact_url, stream=True, timeout=30) 
        response.raise_for_status()  
        with open(full_download_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192): f.write(chunk)
        logging.info(f"Successfully downloaded {artifact_name}")
        return full_download_path
    except requests.exceptions.HTTPError as e: logging.error(f"HTTP error downloading {artifact_name} from {artifact_url}: {e}")
    except requests.exceptions.ConnectionError as e: logging.error(f"Connection error downloading {artifact_name} from {artifact_url}: {e}")
    except requests.exceptions.Timeout: logging.error(f"Timeout downloading {artifact_name} from {artifact_url}")
    except Exception as e: logging.error(f"Failed to download {artifact_name} from {artifact_url}: {e}", exc_info=True)
    return None

if __name__ == "__main__":
    main()
