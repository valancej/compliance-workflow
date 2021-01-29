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
    parser.add_argument('-t', '--tool', help='tool used to generate results. ex. anchore-grype')

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
def create_report(content, stage, stage_number, compliance_standard, input_file, tool):
   
    results_dict = process_input_results_file(input_file)

    current_time = datetime.datetime.now()
    git_sha = os.getenv('GITHUB_SHA')

    report_content = {
        "timestamp": current_time.strftime("%c"),
        "stage": stage,
        "stage_number": stage_number,
        "git_sha": git_sha,
        "tool": {},
        "compliance": {
            "name": compliance_standard,
            "sections": []
        },
        "tool_result_data": results_dict,
        "manifest_info": content
    }

    if stage == 'source':
       print("source stage found")
       report_content["tool"]["name"] = tool
       report_content["compliance"]["sections"].append({
           'description': 'Images should be scanned frequently for any vulnerabilities', 'name': '4.4'
        })
           
    elif stage == 'build':
        print('build stage found')
        # Could also be anchore enterprise scan
        report_content["tool"]["name"] = 'anchore-grype'
        report_content["compliance"]["sections"].append({
           'description': 'Images should be scanned frequently for any vulnerabilities',
           'name': '4.4'
        })
    
    elif stage == 'registry':
        print('registry stage found')
        report_content["tool"]["name"] = 'anchore-enterprise'
        report_content["compliance"]["sections"] = [
            {
                'description': 'Ensure a container for the user has been created',
                'name': '4.1'
            },
            {
                'description': 'Ensure containers use trusted base images',
                'name': '4.2'
            },
            {
                'description': 'Ensure that unnecessary packages are not installed in the container',
                'name': '4.3'
            },
            {
                'description': 'Images should be scanned frequently for any vulnerabilities',
                'name': '4.5'
            },            
            {
                'description': 'Ensure HEALTHCHECK instructions have been added',
                'name': '4.6'
            },
            {
                'description': 'Ensure update instructions are not used alone in the Dockerfile',
                'name': '4.7'
            },
            {
                'description': 'Ensure setuid and setgid permissions are removed',
                'name': '4.8'
            },
            {
                'description': 'Ensure that COPY is used instead of ADD',
                'name': '4.9'
            },
            {
                'description': 'Ensure secrets are not stored',
                'name': '4.10'
            },
            {
                'description': 'Ensure only necessary ports are open',
                'name': '5.8'
            }
        ]
    
    elif stage == 'k8s':
        print('kube-bench stage found. looking for kube-bench report')
        report_content["tool"]["name"] = 'kube-bench'
        report_content["compliance"]["sections"] = [
            {
                'description': "Control Plane Components",
                'name': '1'
            },
            {
                'description': "Control Plane Configuration",
                'name': '2'
            },
            {
                'description': "Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive",
                'name': '3.1.1'
            },
            {
                'description': "Ensure that the proxy kubeconfig file ownership is set to root:root",
                'name': '3.1.2'
            },
            {
                'description': "Ensure that the kubelet configuration file has permissions set to 644 or more restrictive",
                'name': '3.1.3'
            },
            {
                'description': "Ensure that the kubelet configuration file ownership is set to root:root ",
                'name': '3.1.4'
            },            
            {
                'description': "Ensure that the --anonymous-auth argument is set to false",
                'name': '3.2.1'
            },
            {
                'description': "Ensure that the --authorization-mode argument is not set to AlwaysAllow",
                'name': '3.2.2'
            },
            {
                'description': "Ensure that the --client-ca-file argument is set as appropriate",
                'name': '3.2.3'
            },
            {
                'description': "Ensure that the --read-only-port argument is set to 0",
                'name': '3.2.4'
            },
            {
                'description': "Ensure that the --streaming-connection-idle-timeout argument is not set to 0",
                'name': '3.2.5'
            },
            {
                'description': "Ensure that the --protect-kernel-defaults argument is set to true",
                'name': '3.2.6'
            },
            {
                'description': "Ensure that the --make-iptables-util-chains argument is set to true",
                'name': '3.2.7'
            },
            {
                'description': "Ensure that the --hostname-override argument is not set",
                'name': '3.2.8'
            },
            {
                'description': "Ensure that the --event-qps argument is set to 0 or a level which ensures appropriate event capture",
                'name': '3.2.9'
            },
            {
                'description': "Ensure that the --rotate-certificates argument is not set to false",
                'name': '3.2.10'
            },
            {
                'description': "Ensure that the RotateKubeletServerCertificate argument is set to true",
                'name': '3.2.11'
            }
        ]

    elif stage == 'deploy':
        print('deploy stage found')
        report_content["tool"]["name"] = 'anchore-cis-bench'
        report_content["compliance"]["sections"] = [
            {
                "description": "Host configuration",
                "name": "1.1.1-1.2.12"
            },
            {
                "description": "Ensure network traffic is restricted between containers on the default bridge",
                "name": "2.1"
            },
            {
                "description": "Ensure the logging level is set to 'info'",
                "name": "2.2"
            },
            {
                "description": "Ensure Docker is allowed to make changes to iptables",
                "name": "2.3"
            },
            {
                "description": "Ensure insecure registries are not used",
                "name": "2.4"
            },
            {
                "description": "Ensure aufs storage driver is not used",
                "name": "2.5"
            },
            {
                "description": "Ensure TLS authentication for Docker daemon is configured",
                "name": "2.6"
            },
            {
                "description": "Ensure the default ulimit is configured appropriately",
                "name": "2.7"
            },
            {
                "description": "Enable user namespace support",
                "name": "2.8"
            },
            {
                "description": "Ensure the default cgroup usage has been confirmed",
                "name": "2.9"
            },
            {
                "description": "Ensure base device size is not changed until needed",
                "name": "2.10"
            },
            {
                "description": "Ensure that authorization for Docker client commands is enabled",
                "name": "2.11"
            },
            {
                "description": "Ensure centralized and remote logging is configured",
                "name": "2.12"
            },
            {
                "description": "Ensure live restore is enabled",
                "name": "2.13"
            },
            {
                "description": "Ensure Userland Proxy is Disabled",
                "name": "2.14"
            },
            {
                "description": "Ensure that a daemon-wide custom seccomp profile is applied if appropriate",
                "name": "2.15"
            },
            {
                "description": "Ensure that experimental features are not implemented in production",
                "name": "2.16"
            },
            {
                "description": "Ensure containers are restricted from acquiring new privileges",
                "name": "2.17"
            },
            {
                "description": "Docker daemon configuration files",
                "name": "3.1-3.22"
            },
            {
                'description': "Ensure that, if applicable, an AppArmor Profile is enabled",
                'name': '5.1'
            },
            {
                'description': "Ensure that, if applicable, SELinux security options are set",
                'name': '5.2'
            },
            {
                'description': "Ensure that Linux kernel capabilities are restricted within containers",
                'name': '5.3'
            },
            {
                'description': "Ensure that privileged containers are not used",
                'name': '5.4'
            },            
            {
                'description': "Ensure sensitive host system directories are not mounted on containers ",
                'name': '5.5'
            },
            {
                'description': "Ensure sshd is not run within containers",
                'name': '5.6'
            },
            {
                'description': "Ensure privileged ports are not mapped within containers",
                'name': '5.7'
            },
            {
                'description': "Ensure that only needed ports are open on the container",
                'name': '5.8'
            },
            {
                'description': "Ensure that the host's network namespace is not shared",
                'name': '5.9'
            },
            {
                'description': "Ensure that the memory usage for containers is limited",
                'name': '5.10'
            },
                        {
                'description': "Ensure that CPU priority is set appropriately on containers",
                'name': '5.11'
            },
            {
                'description': "Ensure that the container's root filesystem is mounted as read only",
                'name': '5.12'
            },
            {
                'description': "Ensure that incoming container traffic is bound to a specific host interface",
                'name': '5.13'
            },
            {
                'description': "Ensure that the 'on-failure' container restart policy is set to 5",
                'name': '5.14'
            },            
            {
                'description': "Ensure that the host's process namespace is not shared",
                'name': '5.15'
            },
            {
                'description': "Ensure that the host's IPC namespace is not shared",
                'name': '5.16'
            },
            {
                'description': "Ensure that host devices are not directly exposed to containers ",
                'name': '5.17'
            },
            {
                'description': "Ensure that the default ulimit is overwritten at runtime if needed",
                'name': '5.18'
            },
            {
                'description': "Ensure mount propagation mode is not set to shared ",
                'name': '5.19'
            },
            {
                'description': "Ensure that the host's UTS namespace is not shared",
                'name': '5.20'
            },
                        {
                'description': "Ensure the default seccomp profile is not Disabled",
                'name': '5.21'
            },
            {
                'description': "Ensure that docker exec commands are not used with the privileged option",
                'name': '5.22'
            },
            {
                'description': "Ensure that docker exec commands are not used with theuser=root option",
                'name': '5.23'
            },
            {
                'description': "Ensure that cgroup usage is confirmed",
                'name': '5.24'
            },            
            {
                'description': "Ensure that the container is restricted from acquiring additional privileges",
                'name': '5.25'
            },
            {
                'description': "Ensure that container health is checked at runtime",
                'name': '5.26'
            },
            {
                'description': "Ensure that Docker commands always make use of the latest version of their image",
                'name': '5.27'
            },
            {
                'description': 'Ensure that the PIDs cgroup limit is used',
                'name': '5.28'
            },
            {
                'description': "Ensure that Docker's default bridge docker0 is not used",
                'name': '5.29'
            },
            {
                'description': "Ensure that the host's user namespaces are not shared",
                'name': '5.30'
            },
            {
                'description': 'Ensure that the Docker socket is not mounted inside any containers',
                'name': '5.31'
            },
            {
                'description': 'Ensure that image sprawl is avoided',
                'name': '6.1'
            },
            {
                'description': 'Ensure that container sprawl is avoided',
                'name': '6.2'
            }
        ]

    with open("stage_outputs/"+ stage + ".json", "w") as file:
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
    tool = args.tool

    # Process manifest from yaml
    create_report(content, stage, stage_number, compliance_standard, input_file, tool)
    
if __name__ == "__main__":
    try:
        arg_parser = setup_parser()
        main(arg_parser)
    except Exception as error:
        print ("\n\nERROR executing script - Exception: {}".format(error))
        sys.exit(1)