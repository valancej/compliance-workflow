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

###### Setup command line parser
def setup_parser():
    parser = argparse.ArgumentParser(description="Tool for generating compliance reports per CI/CD stage")
    parser.add_argument('-s', '--stage', default='none', help='Pipeline step/stage name. ex. directory, image, registry, deploy')
    parser.add_argument('-n', '--number', default='none', type=int, help='Pipeline step/stage number. ex. 1, 2, 3')
    parser.add_argument('-c', '--compliance', default='cis', help='compliance check to evaluate. ex. cis')
    parser.add_argument('-f', '--file', default='vulnerabilities.json', help='path to output results file from previous tool to attach to report. ex. grype vulnerabilities.json')

    return parser

###### Loads a json input file from a security tool such as Grype or Anchore
def process_input_results_file(input_file):
    # Load results file from tool into dict
    input_file_path = Path(input_file)
    if input_file_path.exists():
        with open(input_file_path, 'r') as stream:
            input_file_dict = json.load(stream)
            return input_file_dict
    else:
        print("Could not find input file")

###### Processes YAML and builds new report output
def create_report(content, stage, stage_number, compliance_standard, input_file):
   
    results_dict = process_input_results_file(input_file)

    current_time = datetime.datetime.now()
    git_sha = os.getenv('GITHUB_SHA')

    report_content = content
    report_content["stage"] = stage
    report_content["stage_number"] = stage_number
    report_content["stage_timestamp"] = current_time.strftime("%c")
    report_content["git_sha"] = git_sha
    report_content["full_image_tag"] = content["image_name"] + ":" + git_sha
    report_content["type"] = 'compliance_check'
    report_content["results"] = results_dict

    compliance_checks = {}
    compliance_checks["compliance_standard"] = compliance_standard

    if stage == 'directory':
       print("directory stage found")
       compliance_checks["tool"] = 'Grype'
       compliance_checks["compliance_sections"] = {
           '4.4': {
               'description': 'Images should be scanned frequently for any vulnerabilities',
           }
        }
       
       report_content.update(compliance_checks)
    
    elif stage == 'build':
        print('build stage found')
        # Could also be anchore enterprise scan
        compliance_checks["tool"] = 'Grype'
        compliance_checks["compliance_sections"] = {
            '4.4': {
                'description': 'Images should be scanned frequently for any vulnerabilities',
            }
        }
        report_content.update(compliance_checks)
    
    elif stage == 'registry':
        print('registry stage found')
        compliance_checks["tool"] = 'Anchore Enterprise'
        compliance_checks["compliance_sections"] = {
            '4.1': {
                'description': 'Ensure a container for the user has been created',
            },
            '4.2': {
                'description': 'Ensure containers use trusted base images',
            },
            '4.3': {
                'description': 'Ensure that unnecessary packages are not installed in the container',
            },
            '4.4': {
                'description': 'Images should be scanned frequently for any vulnerabilities',
            },            
            '4.6': {
                'description': 'Ensure HEALTHCHECK instructions have been added',
            },
            '4.7': {
                'description': 'Ensure update instructions are not used alone in the Dockerfile',
            },
            '4.8': {
                'description': 'Ensure setuid and setgid permissions are removed',
            },
            '4.9': {
                'description': 'Ensure that COPY is used instead of ADD',
            },
            '4.10': {
                'description': 'Ensure secrets are not stored',
            },
            '5.8': {
                'description': 'Ensure only necessary ports are open',
            }
        }

        report_content.update(compliance_checks)
    
    elif stage == 'kube-bench':
        print('kube-bench stage found. looking for kube-bench report')
        compliance_checks["tool"] = 'kube-bench'

        report_content.update(compliance_checks)

    elif stage == 'deploy':
        print('deploy stage found')
        compliance_checks["tool"] = 'Anchore Enterprise'

        report_content.update(compliance_checks)


    with open("artifacts/"+ stage + "-compliance-report.json", "w") as file:
       json.dump(report_content, file)

def main(arg_parser):

    # Load compliance manifest yaml
    compliance_manifest_yaml_path = Path("compliance_manifest.yaml")
    if compliance_manifest_yaml_path.exists():
        with open(compliance_manifest_yaml_path, 'r') as stream:
            try:
                content = yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
    else:
        print("Could not find compliance manifest file in repository root directory")

    parser = arg_parser
    args = parser.parse_args()
    stage = args.stage
    stage_number = args.number
    compliance_standard = args.compliance
    input_file = args.file

    # Process manifest from yaml
    create_report(content, stage, stage_number, compliance_standard, input_file)
    
if __name__ == "__main__":
    try:
        arg_parser = setup_parser()
        main(arg_parser)
    except Exception as error:
        print ("\n\nERROR executing script - Exception: {}".format(error))
        sys.exit(1)