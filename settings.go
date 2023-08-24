package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

var (
	MOONSTREAM_ACCESS_TOKEN        = os.Getenv("MOONSTREAM_ACCESS_TOKEN")
	MOONSTREAM_API_URL             = os.Getenv("MOONSTREAM_API_URL")
	MOONSTREAM_API_TIMEOUT_SECONDS = os.Getenv("MOONSTREAM_API_TIMEOUT_SECONDS")

	BUGOUT_ACCESS_TOKEN = os.Getenv("BUGOUT_ACCESS_TOKEN")

	WAGGLE_CORS_ALLOWED_ORIGINS = os.Getenv("WAGGLE_CORS_ALLOWED_ORIGINS")
)

type ServerSignerConfig struct {
	KeyfilePath         string `json:"keyfile_path"`
	KeyfilePasswordPath string `json:"keyfile_password_path"`
}

// ReadConfig parses list of configuration file paths to list of Application Probes configs
func ReadServerSignerConfig(rawConfigPath string) (*[]ServerSignerConfig, error) {
	var configs []ServerSignerConfig

	configPath := strings.TrimSuffix(rawConfigPath, "/")
	_, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file %s not found, err: %v", configPath, err)
		}
		return nil, fmt.Errorf("error due checking config path %s, err: %v", configPath, err)
	}

	rawBytes, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	configTemp := &[]ServerSignerConfig{}
	err = json.Unmarshal(rawBytes, configTemp)
	if err != nil {
		return nil, err
	}

	for _, ct := range *configTemp {
		_, err := os.Stat(ct.KeyfilePath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("Signer ignored, file %s not found, err: %v\n", ct.KeyfilePath, err)
				continue
			}
			log.Printf("Signer ignored, error due checking config path %s, err: %v\n", ct.KeyfilePath, err)
			continue
		}
		_, err = os.Stat(ct.KeyfilePasswordPath)
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("Signer ignored, file %s not found, err: %v\n", ct.KeyfilePasswordPath, err)
				continue
			}
			log.Printf("Signer ignored, error due checking config path %s, err: %v\n", ct.KeyfilePasswordPath, err)
			continue
		}
		configs = append(configs, ServerSignerConfig{
			KeyfilePath:         ct.KeyfilePath,
			KeyfilePasswordPath: ct.KeyfilePasswordPath,
		})
	}

	return &configs, nil
}
