# dependency_analyzer.py
"""
This script analyzes Maven project dependencies to identify native shared object (.so) files
and checks their ELF alignment for 16KB page size compatibility.
It recursively downloads dependencies, extracts .so files (using file magic numbers, not just extensions),
checks their alignment using objdump, and generates a JSON report.

Example Usage:

# For a Maven project:
python dependency_analyzer.py path/to/your/project/pom.xml path/to/output_report.json

# For a project where specific dependencies (e.g., any under 'com.google.android' group or specifically 'androidx.core:core-ktx') 
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

# Set up basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Gradle-specific parse_gradle_file function has been removed.

def parse_maven_file(file_path):
    """Parses a Maven POM file to extract dependencies."""
    logging.info(f"Parsing Maven file: {file_path}")
    dependencies = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        # Maven POM files use namespaces, so we need to handle them
        namespace = root.tag.split('}')[0] + '}' if '}' in root.tag else ''

        for dependency in root.findall(f".//{namespace}dependency"):
            group_id_element = dependency.find(f"{namespace}groupId")
            artifact_id_element = dependency.find(f"{namespace}artifactId")
            version_element = dependency.find(f"{namespace}version")

            group_id = group_id_element.text if group_id_element is not None else None
            artifact_id = artifact_id_element.text if artifact_id_element is not None else None
            version = version_element.text if version_element is not None else None

            if group_id and artifact_id: # Version can sometimes be managed by parent POM or BOM
                dependencies.append({
                    "groupId": group_id,
                    "artifactId": artifact_id,
                    "version": version
                })
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
    parser.add_argument("output_report_path", help="Path to save the JSON report.")
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

    # The input file is confirmed to be pom.xml, proceed with Maven parsing.
    logging.info(f"Parsing Maven pom.xml file: {args.build_file_path}")
    dependencies = parse_maven_file(args.build_file_path)
    
    # Ensure dependencies is a list for json.dumps, even if it's empty from parsing
    if not isinstance(dependencies, list):
        dependencies = []
    
    logging.info(f"Initial dependencies found: {json.dumps(dependencies, indent=4)}")

    temp_download_dir = tempfile.mkdtemp()
    logging.info(f"Created temporary directory for downloads: {temp_download_dir}")
    
    so_extract_dir = os.path.join(temp_download_dir, "extracted_so_files")
    os.makedirs(so_extract_dir, exist_ok=True)
    logging.info(f"Created directory for extracted .so files: {so_extract_dir}")

    processed_dependencies_set = set()
    # all_downloaded_artifact_paths will now store dicts: {'path': path, 'dependency': dep_dict}
    all_downloaded_artifacts_info = [] 
    all_extracted_so_data = []

    try:
        download_and_extract_dependencies_recursively(
            dependencies,
            temp_download_dir,
            so_extract_dir, # new argument
            args.google_maven_regex,
            processed_dependencies_set,
            all_downloaded_artifacts_info, # modified
            all_extracted_so_data # new argument
        )
        
        logging.info(f"All downloaded artifacts info: {json.dumps(all_downloaded_artifacts_info, indent=2)}")
        logging.info(f"Total .so files extracted: {len(all_extracted_so_data)}")
        if all_extracted_so_data:
            logging.info(f"Extracted .so files data: {json.dumps(all_extracted_so_data, indent=2)}")


    finally:
        logging.info(f"Cleaning up temporary directory: {temp_download_dir}")
        # Using os.walk for robust cleanup as before
        for root, dirs, files in os.walk(temp_download_dir, topdown=False):
            for name in files:
                try:
                    os.remove(os.path.join(root, name))
                except OSError as e:
                    logging.error(f"Error removing file {os.path.join(root, name)}: {e}")
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except OSError as e:
                    logging.error(f"Error removing directory {os.path.join(root, name)}: {e}")
        try:
            os.rmdir(temp_download_dir)
        except OSError as e:
            logging.error(f"Error removing temporary directory {temp_download_dir}: {e}")

    # Perform ELF alignment checks and prepare so_files_analysis_results
    so_files_analysis_results = []
    if all_extracted_so_data:
        logging.info(f"Starting ELF alignment checks for {len(all_extracted_so_data)} .so files...")
        for so_data_item in all_extracted_so_data: # Renamed to avoid conflict
            alignment_info = check_elf_alignment(so_data_item['so_file_path'])
            so_data_item.update(alignment_info) # Merge alignment info into the existing dict
            so_files_analysis_results.append(so_data_item)
        # Logging for alignment counts is now part of summary calculation
    
    # Calculate summary statistics
    total_initial_dependencies = len(dependencies) # 'dependencies' is the initial list
    total_resolved_artifacts = len(all_downloaded_artifacts_info)
    total_so_files_found = len(so_files_analysis_results)
    
    aligned_so_files_count = 0
    unaligned_so_files_count = 0
    error_alignment_check_count = 0

    for item in so_files_analysis_results:
        if item.get('is_aligned'):
            aligned_so_files_count += 1
        elif item.get('error_message') or item.get('alignment_bytes') is None: # Error or undetermined
            error_alignment_check_count += 1
        else: # Has alignment_bytes, no error_message, but not is_aligned
            unaligned_so_files_count += 1
            
    logging.info(
        f"ELF alignment check complete. Total .so: {total_so_files_found}, "
        f"Aligned: {aligned_so_files_count}, Unaligned: {unaligned_so_files_count}, "
        f"Errors/Undetermined: {error_alignment_check_count}"
    )

    report_summary = {
        "total_initial_dependencies": total_initial_dependencies,
        "total_resolved_artifacts": total_resolved_artifacts,
        "total_so_files_found": total_so_files_found,
        "aligned_so_files_count": aligned_so_files_count,
        "unaligned_so_files_count": unaligned_so_files_count,
        "error_alignment_check_count": error_alignment_check_count
    }

    final_report_data = {
        "summary": report_summary,
        "initial_dependencies": dependencies, # 'dependencies' is the initial list from parsing
        "resolved_artifacts": all_downloaded_artifacts_info,
        "so_files_analysis": so_files_analysis_results
    }
    with open(args.output_report_path, 'w') as f:
        json.dump(final_report_data, f, indent=4)
    logging.info(f"Report saved to {args.output_report_path}")


def extract_so_files_from_archive(artifact_path, so_extract_dir, dependency_info):
    """
    Extracts .so files from a JAR/AAR archive.
    Returns a list of metadata for each extracted .so file.
    """
    extracted_files_metadata = []
    ELF_MIME_TYPES = {'application/x-sharedlib', 'application/x-elf'}

    try:
        with zipfile.ZipFile(artifact_path, 'r') as archive:
            for member_info in archive.infolist():
                if member_info.is_dir():
                    continue

                # Read the beginning of the file to check its type
                try:
                    file_buffer = archive.read(member_info.filename)[:2048] # Read first 2KB
                    if not file_buffer: # Empty file
                        continue
                    mime_type = magic.from_buffer(file_buffer, mime=True)
                except Exception as e: # Broad exception for magic library issues
                    logging.warning(f"Could not determine MIME type for {member_info.filename} in {artifact_path} using python-magic: {e}")
                    # Fallback to extension check if magic fails for some reason
                    if not member_info.filename.endswith(".so"):
                        continue # Skip if not .so and magic failed
                    mime_type = 'application/x-sharedlib' # Assume it's an SO if extension matches and magic failed

                if mime_type in ELF_MIME_TYPES:
                    original_filename_from_archive = os.path.basename(member_info.filename)
                    
                    if not original_filename_from_archive.endswith(".so") and mime_type == 'application/x-sharedlib':
                        logging.info(
                            f"File '{original_filename_from_archive}' in {artifact_path} "
                            f"identified as ELF shared library by magic, but does not have .so extension."
                        )
                    elif mime_type == 'application/x-elf':
                         logging.info(
                            f"File '{original_filename_from_archive}' in {artifact_path} "
                            f"identified as a generic ELF file by magic (MIME: {mime_type})."
                        )


                    # Construct a unique name, ensuring it ends with .so
                    # Example: group_artifact_version_original_filename.so
                    # If original was libnative.so, it becomes g_a_v_libnative.so
                    # If original was just 'native_lib', it becomes g_a_v_native_lib.so
                    base_unique_filename = (
                        f"{dependency_info['groupId']}_{dependency_info['artifactId']}_"
                        f"{dependency_info['version']}_{original_filename_from_archive}"
                    ).replace(':', '_').replace('-', '_').replace('/', '_') # Sanitize more

                    # Ensure the final name has .so extension
                    if not base_unique_filename.endswith(".so"):
                        unique_so_filename = f"{base_unique_filename}.so"
                    else:
                        unique_so_filename = base_unique_filename
                    
                    target_so_path = os.path.join(so_extract_dir, unique_so_filename)
                    
                    try:
                        # Extract the file content (already read part of it for magic)
                        # Re-open for full content to ensure atomicity of write
                        with archive.open(member_info.filename) as source, open(target_so_path, 'wb') as target:
                            target.write(source.read())
                        
                        logging.info(f"Extracted ELF file: '{original_filename_from_archive}' to '{target_so_path}' from {dependency_info['artifactId']}")
                        
                        extracted_files_metadata.append({
                            "so_file_path": target_so_path,
                            "original_so_filename": original_filename_from_archive, # Original name from archive
                            "dependency_group": dependency_info['groupId'],
                            "dependency_artifact": dependency_info['artifactId'],
                            "dependency_version": dependency_info['version'],
                            "mime_type_detected": mime_type
                        })
                    except Exception as e_extract:
                        logging.error(f"Error extracting {member_info.filename} to {target_so_path}: {e_extract}", exc_info=True)

    except zipfile.BadZipFile:
        logging.error(f"Bad ZIP file: {artifact_path}", exc_info=True)
    except Exception as e_zip: # Catch other zip-related errors
        logging.error(f"Error processing archive {artifact_path}: {e_zip}", exc_info=True)
    return extracted_files_metadata


def check_elf_alignment(so_file_path):
    """
    Checks ELF alignment of a .so file using objdump.
    Returns a dictionary with alignment details.
    """
    cmd = ["objdump", "-p", so_file_path]
    result = {
        'alignment_value_str': None,
        'alignment_bytes': None,
        'is_aligned': False,
        'error_message': None
    }
    min_alignment_bytes = 16384  # 16KB (2**14)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            result['error_message'] = f"objdump failed with return code {proc.returncode}. Stderr: {proc.stderr.strip()}"
            logging.error(f"objdump error for {so_file_path}: {result['error_message']}")
            return result
        
        output = proc.stdout
        
        # Find the first LOAD segment's alignment
        # Example lines from objdump -p output:
        # Program Header:
        #     LOAD off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**21
        #          filesz 0x0000000000687334 memsz 0x0000000000687334 flags r-x
        #     LOAD off    0x0000000000688000 vaddr 0x0000000000888000 paddr 0x0000000000888000 align 2**21
        #          filesz 0x00000000000380e8 memsz 0x0000000000039ea0 flags rw-
        #
        # Sometimes alignment is given as a hex value:
        #     LOAD off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 0x200000
        
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
                result['error_message'] = f"Unknown alignment format: {alignment_str}"
                logging.warning(result['error_message'])

        if alignment_bytes is not None:
            result['alignment_bytes'] = alignment_bytes
            if alignment_bytes >= min_alignment_bytes:
                result['is_aligned'] = True
            logging.info(f"File: {so_file_path}, Align String: '{alignment_str}', Bytes: {alignment_bytes}, Aligned: {result['is_aligned']}")
        else:
            logging.warning(f"Could not determine alignment in bytes for {so_file_path} from string '{alignment_str}'")


    except FileNotFoundError:
        result['error_message'] = "objdump command not found. Please ensure binutils is installed."
        logging.error(result['error_message'])
    except Exception as e:
        result['error_message'] = f"An unexpected error occurred during alignment check: {str(e)}"
        logging.error(f"{result['error_message']} for {so_file_path}", exc_info=True)
        
    return result


def download_and_extract_dependencies_recursively(
    dependencies_to_process,
    temp_dir,
    so_extract_dir, # new
    google_maven_regex_str,
    processed_dependencies_set,
    all_downloaded_artifacts_info, # modified
    all_extracted_so_data # new
):
    """
    Downloads dependencies, their POMs, parses transitive dependencies, 
    recursively downloads them, and extracts .so files.
    """
    for dep in dependencies_to_process:
        current_dependency_info = { # Store full dep info for use later
            "groupId": dep.get("groupId"),
            "artifactId": dep.get("artifactId"),
            "version": dep.get("version")
            # Potentially add scope, optional, etc. if parsed from POMs in the future
        }

        if not current_dependency_info["groupId"] or \
           not current_dependency_info["artifactId"] or \
           not current_dependency_info["version"]:
            logging.warning(f"Skipping dependency with missing GAV: {current_dependency_info}")
            continue

        dependency_identifier = f"{current_dependency_info['groupId']}:{current_dependency_info['artifactId']}:{current_dependency_info['version']}"
        if dependency_identifier in processed_dependencies_set:
            logging.info(f"Skipping already processed dependency: {dependency_identifier}")
            continue
        processed_dependencies_set.add(dependency_identifier)
        logging.info(f"Processing dependency: {dependency_identifier}")

        repo_url = get_repository_url(current_dependency_info, google_maven_regex_str)

        # 1. Download POM
        pom_url = construct_artifact_url(current_dependency_info, repo_url, artifact_type="pom")
        pom_filename = f"{current_dependency_info['artifactId']}-{current_dependency_info['version']}.pom"
        downloaded_pom_path = download_artifact(pom_url, temp_dir, pom_filename)

        transitive_dependencies = []
        if downloaded_pom_path:
            logging.info(f"Successfully downloaded POM: {pom_filename} from {pom_url}")
            # Parse the downloaded POM for its dependencies
            # Note: parse_maven_file expects a filepath, so we give it the downloaded_pom_path
            transitive_dependencies = parse_maven_file(downloaded_pom_path)
            logging.info(f"Found {len(transitive_dependencies)} transitive dependencies in {pom_filename}")
        else:
            logging.warning(f"Failed to download POM for {dependency_identifier} from {pom_url}. Transitive dependencies will not be processed.")

        # 2. Recursively process transitive dependencies (done *before* downloading main artifact of current dep)
        if transitive_dependencies:
            download_and_extract_dependencies_recursively(
                transitive_dependencies,
                temp_dir,
                so_extract_dir,
                google_maven_regex_str,
                processed_dependencies_set,
                all_downloaded_artifacts_info,
                all_extracted_so_data
            )
        
        # 3. Download the main artifact (JAR/AAR)
        # TODO: Determine packaging (jar, aar, etc.) from POM's <packaging> tag. Default to 'jar'.
        # This info might be available if we parse the POM more deeply earlier or pass it along.
        # For now, assume 'jar' but could be 'aar' for Android.
        # Let's assume 'jar' for now, but if it were 'aar', the .so extraction would still work.
        artifact_type_from_pom = "jar" # Placeholder
        
        main_artifact_url = construct_artifact_url(current_dependency_info, repo_url, artifact_type=artifact_type_from_pom)
        if not main_artifact_url: # In case version was missing etc.
            logging.error(f"Could not construct URL for main artifact of {dependency_identifier}")
            # No artifact to download or process for .so files
            # Continue to next dependency in the list
            continue 
            
        main_artifact_filename = f"{current_dependency_info['artifactId']}-{current_dependency_info['version']}.{artifact_type_from_pom}"
        
        downloaded_main_artifact_path = download_artifact(main_artifact_url, temp_dir, main_artifact_filename)

        if downloaded_main_artifact_path:
            logging.info(f"Successfully downloaded main artifact: {main_artifact_filename} from {main_artifact_url}")
            all_downloaded_artifacts_info.append({
                "path": downloaded_main_artifact_path,
                "dependency": current_dependency_info # Store the GAV info
            })
            
            # 4. Extract .so files from the downloaded artifact
            so_files_in_artifact = extract_so_files_from_archive(
                downloaded_main_artifact_path, 
                so_extract_dir, 
                current_dependency_info
            )
            if so_files_in_artifact:
                all_extracted_so_data.extend(so_files_in_artifact)
        else:
            logging.error(f"Failed to download main artifact for {dependency_identifier} from {main_artifact_url}")


def get_repository_url(dependency, google_maven_regex_str):
    """Determines the repository URL for a given dependency."""
    if google_maven_regex_str:
        try:
            google_maven_regex = re.compile(google_maven_regex_str)
            if google_maven_regex.search(dependency.get("groupId", "")) or \
               google_maven_regex.search(dependency.get("artifactId", "")):
                logging.info(f"Using Google Maven for {dependency['groupId']}:{dependency['artifactId']}")
                return "https://maven.google.com/"
        except re.error as e:
            logging.warning(f"Invalid regex provided for Google Maven: {google_maven_regex_str}. Error: {e}")
    
    logging.info(f"Using Maven Central for {dependency['groupId']}:{dependency['artifactId']}")
    return "https://repo.maven.apache.org/maven2/"


def construct_artifact_url(dependency, base_repo_url, artifact_type="jar"):
    """Constructs the artifact URL for a dependency (POM, JAR, AAR, etc.)."""
    group_path = dependency["groupId"].replace('.', '/')
    artifact_id = dependency["artifactId"]
    version = dependency["version"]

    if not version: # Handle cases where version might be missing (e.g. managed by parent)
        logging.warning(f"Version is missing for {dependency['groupId']}:{dependency['artifactId']}. Cannot construct URL.")
        return None # Or raise an error

    artifact_filename_base = f"{artifact_id}-{version}"
    
    # Construct URL based on artifact_type (pom, jar, aar, etc.)
    artifact_url = f"{base_repo_url}{group_path}/{artifact_id}/{version}/{artifact_filename_base}.{artifact_type}"
    
    return artifact_url


def download_artifact(artifact_url, download_path, artifact_name):
    """Downloads an artifact from a given URL to a specified path."""
    full_download_path = os.path.join(download_path, artifact_name)
    try:
        logging.info(f"Attempting to download: {artifact_url} to {full_download_path}")
        response = requests.get(artifact_url, stream=True, timeout=30) # Added timeout
        response.raise_for_status()  # Will raise an HTTPError for bad responses (4XX or 5XX)
        
        with open(full_download_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        logging.info(f"Successfully downloaded {artifact_name}")
        return full_download_path
    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error downloading {artifact_name} from {artifact_url}: {e}")
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error downloading {artifact_name} from {artifact_url}: {e}")
    except requests.exceptions.Timeout:
        logging.error(f"Timeout downloading {artifact_name} from {artifact_url}")
    except Exception as e:
        logging.error(f"Failed to download {artifact_name} from {artifact_url}: {e}", exc_info=True)
    return None


if __name__ == "__main__":
    main()
