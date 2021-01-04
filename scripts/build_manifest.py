#!/usr/bin/python3
import argparse
import datetime
import os
import json
import sys
import yaml
from pathlib import Path

## Example stepping through the stages of a pipeline
# 1. Directory or source code scan using Grype
# 2. Scan built image with Grype or Anchore Enterprise
# 3. Scan built image in registry with Anchore Enterprise
# 4. Evaluate K8s / runtime environment
# 
# Generate a single report per stage including: 
# - vuln / compliance information from tool used (Grype, Anchore Enterprise, etc.)
# - metadata (timestamp, git sha, image name, etc.)

def setup_parser():
    parser = argparse.ArgumentParser(description="Tool for generating compliance reports per CI/CD stage")
    parser.add_argument('-s', '--stage', default='none', help='Pipeline step/stage name. ex. directory, image, registry')
    parser.add_argument('-c', '--compliance', default='cis', help='compliance check to evaluate. ex. cis')

    return parser

def main(arg_parser):

    # Load compliance manifest yaml
    compliance_manifest_yaml_path = Path("compliance_manifest.yaml")
    if compliance_manifest_yaml_path.exists():
        with open("compliance_manifest.yaml", 'r') as stream:
            try:
                content = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
    else:
        print("Could not find hardening manifest file in repository root directory")

    # Process manifest from yaml

    parser = arg_parser
    args = parser.parse_args()
    stage = args.stage
    compliance_standard = args.compliance

    process_manifest(content, stage, compliance_standard)

def process_manifest(content, stage, compliance_standard):
   
    current_time = datetime.datetime.now()

    manifest_content = content
    manifest_content["stage"] = stage
    manifest_content["stage_timestamp"] = current_time.strftime("%c")
    manifest_content["git_sha"] = os.getenv('GITHUB_SHA')
    #manifest_content["git_sha"] = "sha12349876235"
    manifest_content["type"] = 'compliance_check'
    compliance_checks = {}
    compliance_checks["compliance_standard"] = compliance_standard

    ## Example stepping through the stages of a pipeline
    # 1. Directory or source code scan using Grype
    # 2. Scan built image with Grype or Anchore Enterprise
    # 3. Scan built image in registry with Anchore Enterprise
    # 4. Evaluate K8s / runtime environment

    if stage == 'directory':
       print("directory stage found")
       compliance_checks["compliance_sections"] = {
           '4.4': {
               'description': 'Images should be scanned frequently for any vulnerabilities',
               'tool': 'Grype scans directory for vulnerabilities' 
           }
        }
       
       manifest_content.update(compliance_checks)
    
    elif stage == 'build':
        print('build stage found')
        compliance_checks["compliance_sections"] = {
            '4.4': {
                'description': 'Images should be scanned frequently for any vulnerabilities',
                'tool': 'Grype scans image for vulnerabilities' 
            }
        }
        manifest_content.update(compliance_checks)
        
    
    elif stage == 'registry':
        print('registry stage found')
        compliance_checks["compliance_sections"] = {
            '4.3': {
                'description': 'Ensure that unnecessary packages are not installed in the container',
                'tool': 'Anchore Enterprise can blacklist packages' 
            },
            '4.4': {
                'description': 'Images should be scanned frequently for any vulnerabilities',
                'tool': 'Anchore Enterprise can scan packages at registry level' 
            }

        }

        manifest_content.update(compliance_checks)
    
    elif stage == 'runtime':
        print('runtime stage found')
        compliance_checks["compliance_sections"] = ''

        manifest_content.update(compliance_checks)


    with open("artifacts/"+ stage + "-compliance-manifest.json", "w") as file:
       json.dump(manifest_content, file)
    
if __name__ == "__main__":
    try:
        arg_parser = setup_parser()
        main(arg_parser)
    except Exception as error:
        print ("\n\nERROR executing script - Exception: {}".format(error))
        sys.exit(1)