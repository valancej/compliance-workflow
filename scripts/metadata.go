package main

import (
	"bufio"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type ComplianceManifest struct {
	Name      string                 `yaml:"name"`
	ImageName string                 `yaml:"imageName"`
	Labels    map[string]interface{} `yaml:"labels"`
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	complianceYaml, err := ioutil.ReadFile("compliance_manifest.yaml")
	check(err)

	var complianceManiest ComplianceManifest

	err = yaml.Unmarshal([]byte(complianceYaml), &complianceManiest)
	check(err)

	file, err := os.Create("artifacts/image-labels.env")
	check(err)

	defer file.Close()

	w := bufio.NewWriter(file)

	for key, value := range complianceManiest.Labels {
		str := fmt.Sprint(value)
		newstr := key + "=" + str + "\n"
		w.WriteString(newstr)
	}

	w.Flush()

}
