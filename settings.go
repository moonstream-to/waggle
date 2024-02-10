package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
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

	BROOD_API_URL              = os.Getenv("BUGOUT_AUTH_URL")
	SPIRE_API_URL              = os.Getenv("BUGOUT_SPIRE_URL")
	BUGOUT_API_TIMEOUT_SECONDS = os.Getenv("BUGOUT_API_TIMEOUT_SECONDS")

	BUGOUT_ACCESS_TOKEN = os.Getenv("BUGOUT_ACCESS_TOKEN")

	WAGGLE_CORS_ALLOWED_ORIGINS = os.Getenv("WAGGLE_CORS_ALLOWED_ORIGINS")

	BUGOUT_RESOURCE_TYPE_WAGGLE_ACCESS = "waggle-access"

	CASER = cases.Title(language.English)
)

type ServerSignerConfigParsed struct {
	Keyfile  []byte
	Password string
}

type ServerSignerConfig struct {
	Keyfile      string `json:"keyfile"`
	KeyfileType  string `json:"keyfile_type"`
	Password     string `json:"password"`
	PasswordType string `json:"password_type"`
}

type ServerConfig struct {
	AccessResourceId string               `json:"access_resource_id"`
	Signers          []ServerSignerConfig `json:"signers"`
}

type KeyfileType string
type PasswordType string

const (
	AwsSecretKeyfile    KeyfileType = "aws_secret"
	EnvVarKeyfilePath   KeyfileType = "env_var"
	TextFileKeyfilePath KeyfileType = "file"

	AwsSecretPassword PasswordType = "aws_secret"
	EnvVarPassword    PasswordType = "env_var"
	PlainTextPassword PasswordType = "plaintext"
	TextFilePassword  PasswordType = "file"
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

func GetAwsSecret(name string) (string, error) {
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
		SecretId:     aws.String(name),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, getSecretErr := svc.GetSecretValue(context.TODO(), input)
	if getSecretErr != nil {
		return "", fmt.Errorf("AWS get secret error, err: %v", getSecretErr.Error())
	}

	// Decrypts secret using the associated KMS key
	return *result.SecretString, nil
}

func GetFileContent(path string) ([]byte, error) {
	_, osStatErr := os.Stat(path)
	if osStatErr != nil {
		if os.IsNotExist(osStatErr) {
			log.Printf("File %s not found, err: %v\n", path, osStatErr)
			return nil, osStatErr
		}
		log.Printf("Error due checking config path %s, err: %v\n", path, osStatErr)
		return nil, osStatErr
	}
	dataRaw, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil, readErr
	}

	return dataRaw, nil
}

// ParseKeyfileInput parses keyfile depends on keyfile type.
func ParseKeyfileInput(input string, inputType KeyfileType) ([]byte, error) {
	switch inputType {
	case AwsSecretKeyfile:
		if badCharsCheckErr := BadCharsCheck(input); badCharsCheckErr != nil {
			return nil, badCharsCheckErr
		}
		keyfileRaw, getSsmErr := GetAwsSecret(input)
		if getSsmErr != nil {
			return nil, getSsmErr
		}
		keyfile, decodeErr := base64.StdEncoding.DecodeString(keyfileRaw)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return keyfile, nil
	case EnvVarKeyfilePath:
		if badCharsCheckErr := BadCharsCheck(input); badCharsCheckErr != nil {
			return nil, badCharsCheckErr
		}
		keyfilePath := os.Getenv(input)
		if keyfilePath == "" {
			return nil, fmt.Errorf("empty environment variable %s input", input)
		}
		keyfile, getFileErr := GetFileContent(keyfilePath)
		return keyfile, getFileErr
	case TextFileKeyfilePath:
		if badCharsCheckErr := BadCharsCheck(input); badCharsCheckErr != nil {
			return nil, badCharsCheckErr
		}
		keyfile, getFileErr := GetFileContent(input)
		return keyfile, getFileErr
	default:
		return nil, fmt.Errorf("unsupported input type provided")
	}
}

// ParsePasswordInput parses password for keyfile depends on password type.
func ParsePasswordInput(input string, inputType PasswordType) (string, error) {
	switch inputType {
	case AwsSecretPassword:
		if badCharsCheckErr := BadCharsCheck(input); badCharsCheckErr != nil {
			return "", badCharsCheckErr
		}
		password, getSsmErr := GetAwsSecret(input)
		return password, getSsmErr
	case EnvVarPassword:
		if badCharsCheckErr := BadCharsCheck(input); badCharsCheckErr != nil {
			return "", badCharsCheckErr
		}
		password := os.Getenv(input)
		if password == "" {
			return "", fmt.Errorf("empty environment variable %s input", input)
		}
		return password, nil
	case PlainTextPassword:
		return input, nil
	case TextFilePassword:
		if badCharsCheckErr := BadCharsCheck(input); badCharsCheckErr != nil {
			return "", badCharsCheckErr
		}
		password, getFileErr := GetFileContent(input)
		return string(password), getFileErr
	default:
		return "", fmt.Errorf("unsupported input type provided")
	}
}

// ReadConfig parses list of configuration file paths to list of Application configuration
func ReadConfig(rawConfigPath string) ([]ServerSignerConfigParsed, string, error) {
	configPath := strings.TrimSuffix(rawConfigPath, "/")
	_, err := os.Stat(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("file %s not found, err: %v", configPath, err)
		}
		return nil, "", fmt.Errorf("error due checking config path %s, err: %v", configPath, err)
	}

	rawBytes, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatal(err)
	}
	configsTemp := &ServerConfig{}
	err = json.Unmarshal(rawBytes, configsTemp)
	if err != nil {
		return nil, "", err
	}

	configParsed := make([]ServerSignerConfigParsed, len(configsTemp.Signers)-1)
	for _, s := range configsTemp.Signers {
		keyfile, keyParseErr := ParseKeyfileInput(s.Keyfile, KeyfileType(s.KeyfileType))
		if keyParseErr != nil {
			return nil, "", keyParseErr
		}

		password, passParseErr := ParsePasswordInput(s.Password, PasswordType(s.PasswordType))
		if passParseErr != nil {
			return nil, "", passParseErr
		}
		configParsed = append(configParsed, ServerSignerConfigParsed{
			Keyfile:  keyfile,
			Password: password,
		})
	}

	return configParsed, configsTemp.AccessResourceId, nil
}
