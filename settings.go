package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	AWS_REGION                     = os.Getenv("AWS_REGION")
	MOONSTREAM_ACCESS_TOKEN        = os.Getenv("MOONSTREAM_ACCESS_TOKEN")
	MOONSTREAM_API_URL             = os.Getenv("MOONSTREAM_API_URL")
	MOONSTREAM_API_TIMEOUT_SECONDS = os.Getenv("MOONSTREAM_API_TIMEOUT_SECONDS")

	BUGOUT_ACCESS_TOKEN = os.Getenv("BUGOUT_ACCESS_TOKEN")

	WAGGLE_CORS_ALLOWED_ORIGINS = os.Getenv("WAGGLE_CORS_ALLOWED_ORIGINS")

	CASER = cases.Title(language.English)
)

type ServerSignerConfig struct {
	KeyfilePath  string `json:"keyfile_path"`
	Password     string `json:"password"`
	PasswordType string `json:"password_type"`
}

// PasswordType specifies available password types
type PasswordType string

const (
	PlainText PasswordType = "plaintext"
	TextFile  PasswordType = "text_file"
	AwsSecret PasswordType = "aws_secret"
)

func BadCharsCheck(input string) error {
	badChars := []string{"%", "&", ";", ">", "<"}
	for _, badChar := range badChars {
		if strings.Contains(input, badChar) {
			return fmt.Errorf("bad char in path: %s", badChar)
		}
	}
	return nil
}

// PasswordValidation validates provided string depends on password type.
// It required bad character check since we are disable HTML escaping for json encoder.
func (pt *PasswordType) PasswordValidation(password string) (string, error) {

	switch *pt {
	case PlainText:
		return password, nil
	case TextFile:
		if badCharsCheckErr := BadCharsCheck(password); badCharsCheckErr != nil {
			return "", badCharsCheckErr
		}
		absPasswordPath, pathCheckErr := filepath.Abs(password)
		if pathCheckErr != nil {
			return "", pathCheckErr
		}
		return absPasswordPath, nil
	case AwsSecret:
		if badCharsCheckErr := BadCharsCheck(password); badCharsCheckErr != nil {
			return "", badCharsCheckErr
		}
		return password, nil
	}

	return "", fmt.Errorf("unable ot validate password")
}

// ParseKeyfilePassword parses password for keyfile depends on password type.
func (ssc *ServerSignerConfig) ParseKeyfilePassword() (string, error) {
	var password string
	switch ssc.PasswordType {
	case string(PlainText):
		password = ssc.Password
	case string(TextFile):
		_, osStatErr := os.Stat(ssc.Password)
		if osStatErr != nil {
			if os.IsNotExist(osStatErr) {
				log.Printf("Signer ignored, file %s not found, err: %v\n", ssc.Password, osStatErr)
				return "", osStatErr
			}
			log.Printf("Signer ignored, error due checking config path %s, err: %v\n", ssc.Password, osStatErr)
			return "", osStatErr
		}
		passwordRaw, readErr := os.ReadFile(ssc.Password)
		if readErr != nil {
			return "", readErr
		}
		password = string(passwordRaw)
	case string(AwsSecret):
		if AWS_REGION == "" {
			return "", fmt.Errorf("AWS_REGION is not specified")
		}

		awsConfig, awsConfigErr := config.LoadDefaultConfig(context.TODO(), config.WithRegion(AWS_REGION))
		if awsConfigErr != nil {
			return "", fmt.Errorf("AWS config load error, err: %v", awsConfigErr)
		}

		// Create Secrets Manager client
		svc := secretsmanager.NewFromConfig(awsConfig)

		input := &secretsmanager.GetSecretValueInput{
			SecretId:     aws.String(ssc.Password),
			VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
		}

		result, getSecretErr := svc.GetSecretValue(context.TODO(), input)
		if getSecretErr != nil {
			return "", fmt.Errorf("AWS get secret error, err: %v", getSecretErr.Error())
		}

		// Decrypts secret using the associated KMS key
		password = *result.SecretString
	}

	return password, nil
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
		password, passParseErr := ct.ParseKeyfilePassword()
		if passParseErr != nil {
			continue
		}
		configs = append(configs, ServerSignerConfig{
			KeyfilePath:  ct.KeyfilePath,
			Password:     password,
			PasswordType: ct.PasswordType,
		})
	}

	return &configs, nil
}
