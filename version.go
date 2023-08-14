package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

func WaggleVersion() string {
	version, err := ioutil.ReadFile("version.txt")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return string(version)
}
