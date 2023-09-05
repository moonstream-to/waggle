package main

import (
	"fmt"
	"os"

	"github.com/moonstream-to/waggle/cmd/waggle"
)

func main() {
	command := waggle.CreateRootCommand()
	err := command.Execute()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
