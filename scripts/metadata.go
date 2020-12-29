package main

import (
	"fmt"
	"os"
	"io/ioutil"
	"gopkg.in/yaml.v2"
	"bufio"
)

type ComplianceManifest struct {
	Name string `yaml:"name"`
	ImageName string `yaml:"imageName"`
	Labels map[string]interface{} `yaml:"labels"`
}

func main() {

	complianceManifestPath := "compliance_manifest.yaml"

	yamlFile, err := os.Open(complianceManifestPath)
	if err != nil {
		fmt.Println(err)
	}
	defer yamlFile.Close()

	complianceYaml, _ := ioutil.ReadAll(yamlFile)

	var complianceManiest ComplianceManifest

	err = yaml.Unmarshal([]byte(complianceYaml), &complianceManiest)
	if err != nil {
		fmt.Println(err)
	}

	file, _ := os.Create("artifacts/image-labels.env")

	defer file.Close()

	w := bufio.NewWriter(file)
 
	for key, value := range complianceManiest.Labels {
		str := fmt.Sprint(value)
		newstr := key + "=" + str + "\n"
		w.WriteString(newstr)
	}

	w.Flush()

}