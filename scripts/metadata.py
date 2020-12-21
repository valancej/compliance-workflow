#!/usr/bin/python3
import os
import json
import yaml
from pathlib import Path

def main(): 
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

    process_manifest(content)

def process_manifest(content):
    # Create image labels file for build script to use
    f = open("artifacts/image-labels.env", "w")
    for key, value in content["labels"].items():
        f.write(f"{key}={value}\n")
    
if __name__ == "__main__":
    main()