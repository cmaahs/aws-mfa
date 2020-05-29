package cmd

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	semVer    string
	gitCommit string
	buildDate string
)

var cfgFile string
var verbose bool

type processParameters struct {
	Profile         string
	Duration        int64
	AssumeRole      string
	ShortTermSuffix string
	RoleSessionName string
	Force           bool
}

type credentialInfo struct {
	AssumedRole        string    `ini:"assumed_role,omitempty"`
	AssumedRoleARN     string    `ini:"assumed_role_arn,omitempty"`
	AwsAccessKeyID     string    `ini:"aws_access_key_id,omitempty"`
	AwsMFADevice       string    `ini:"aws_mfa_device,omitempty"`
	AwsSecretAccessKey string    `ini:"aws_secret_access_key,omitempty"`
	AwsSecurityToken   string    `ini:"aws_security_token,omitempty"`
	AwsSessionToken    string    `ini:"aws_session_token,omitempty"`
	Expiration         time.Time `ini:"expiration,omitempty"`
	Region             string    `ini:"region,omitempty"`
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "aws-mfa",
	Short: `manage short term AWS profiles with MFA`,
	Run: func(cmd *cobra.Command, args []string) {
		profile, _ := cmd.Flags().GetString("profile")
		duration, _ := cmd.Flags().GetInt64("duration")
		assumeRole, _ := cmd.Flags().GetString("assume-role")
		shortTermSuffix, _ := cmd.Flags().GetString("short-term-suffix")
		roleSessionName, _ := cmd.Flags().GetString("role-session-name")
		force, _ := cmd.Flags().GetBool("force")
		verbose, _ = cmd.Flags().GetBool("verbose")
		inParams := &processParameters{
			Profile:         profile,
			Duration:        duration,
			AssumeRole:      assumeRole,
			ShortTermSuffix: shortTermSuffix,
			RoleSessionName: roleSessionName,
			Force:           force,
		}
		// What do we want to capture as output?  Perhaps don't express any
		// data in the 'process' routine, and just return the entire output?
		out, err := process(inParams)
		if err != nil {
			logrus.WithError(err).Error("Error getting Default CR Info")
		}

		// Clearly this does nothing at the moment.
		fmt.Println(out)
	},
}

func errCheck(err error) {
	if err != nil {
		logrus.Fatal(err)
	}
}

func getDefaultCredentialsFilePath(pathOverride string) string {
	usr, err := user.Current()
	errCheck(err)
	filePath := usr.HomeDir + "/.aws/credentials"
	if len(pathOverride) > 0 {
		// TODO: stat the file, see if it actually exists.
		// TODO: Make a --credFilePath parameters, make it persistent, store in cobra config
		filePath = pathOverride
	}

	return filePath
}

// TODO: potentially add error return here.
func getAwsCredentialsFileObject(pathOverride string) *ini.File {

	filePath := getDefaultCredentialsFilePath(pathOverride)
	iniFile, err := ini.Load(filePath)
	errCheck(err)

	return iniFile
}

func saveAwsCredentialsFile(iniFile *ini.File, pathOverride string) error {

	filePath := getDefaultCredentialsFilePath(pathOverride)
	iniFile.SaveTo(filePath)

	return nil
}

func getCredentialInfo(iniFile *ini.File, sectionName string) (credentialInfo, error) {

	sect, err := iniFile.GetSection(sectionName)
	errCheck(err)
	info := &credentialInfo{}
	err = sect.MapTo(info)
	errCheck(err)

	return *info, nil

}

func getAssumedRoleFromSection(iniFile *ini.File, sectionName string) (string, error) {

	sect, err := iniFile.GetSection(sectionName)
	errCheck(err)
	info := &credentialInfo{}
	err = sect.MapTo(info)
	errCheck(err)

	return info.AssumedRoleARN, nil

}

func getAwsStsSession(cred credentialInfo) (*sts.STS, string, error) {
	conf := &aws.Config{
		Region: aws.String(cred.Region),
		Credentials: credentials.NewCredentials(&credentials.StaticProvider{Value: credentials.Value{
			AccessKeyID:     cred.AwsAccessKeyID,
			SecretAccessKey: cred.AwsSecretAccessKey,
		}}),
	}

	sess, err := session.NewSession(conf)

	errCheck(err)

	_iam := iam.New(sess)

	devices, err := _iam.ListMFADevices(&iam.ListMFADevicesInput{})

	errCheck(err)

	if len(devices.MFADevices) == 0 {
		log.Fatal("No MFA devices configured")
	}

	foundMFA := false
	for i := 0; i <= len(devices.MFADevices); i++ {
		if *devices.MFADevices[i].SerialNumber == cred.AwsMFADevice {
			foundMFA = true
			break
		}
	}

	if !foundMFA {
		logrus.Fatal("Your defined MFA devices is not in your List of MFA devices")
	}

	// sn := devices.MFADevices[0].SerialNumber
	sn := cred.AwsMFADevice

	if verbose {
		fmt.Printf("Using device %1s\n", sn)
	}

	return sts.New(sess), sn, nil

}

func readMFACode() string {

	fmt.Printf("Enter MFA code: ")

	r := bufio.NewReader(os.Stdin)
	code, _, err := r.ReadLine()
	errCheck(err)

	return string(code)

}

func process(params *processParameters) (string, error) {

	awsCredsFile := getAwsCredentialsFileObject("")
	longTermProfile := fmt.Sprintf("%s-long-term", params.Profile)
	shortTermProfile := fmt.Sprintf("%s", params.Profile)
	if len(params.ShortTermSuffix) > 0 {
		shortTermProfile = fmt.Sprintf("%s-%s", params.Profile, params.ShortTermSuffix)
	}

	credInfo, _ := getCredentialInfo(awsCredsFile, longTermProfile)

	stsSess, mfaDevice, err := getAwsStsSession(credInfo)
	errCheck(err)

	codeStr := readMFACode()

	if len(params.AssumeRole) > 0 {

		if len(params.RoleSessionName) == 0 {
			logrus.Fatal("--role-session-name is required when you use --assume-role")
		}

		arOutput, err := stsSess.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         &params.AssumeRole,
			RoleSessionName: &params.RoleSessionName,
			SerialNumber:    &mfaDevice,
			TokenCode:       &codeStr,
			DurationSeconds: &params.Duration,
		})
		errCheck(err)

		if verbose {
			fmt.Println("")
			fmt.Println(fmt.Sprintf("aws_access_key_id: %s", *arOutput.Credentials.AccessKeyId))
			fmt.Println(fmt.Sprintf("aws_secret_access_key: %s", *arOutput.Credentials.SecretAccessKey))
			fmt.Println(fmt.Sprintf("aws_session_token: %s", *arOutput.Credentials.SessionToken))
			fmt.Println(fmt.Sprintf("expiration: %s", *arOutput.Credentials.Expiration))
		}
		newCred := &credentialInfo{
			AssumedRole:        "True",
			AssumedRoleARN:     params.AssumeRole,
			AwsAccessKeyID:     *arOutput.Credentials.AccessKeyId,
			AwsSecretAccessKey: *arOutput.Credentials.SecretAccessKey,
			AwsSecurityToken:   *arOutput.Credentials.SessionToken,
			AwsSessionToken:    *arOutput.Credentials.SessionToken,
			Region:             credInfo.Region,
			Expiration:         *arOutput.Credentials.Expiration,
		}

		newSection, err := awsCredsFile.NewSection(shortTermProfile)
		errCheck(err)

		newSection.ReflectFrom(newCred)
	} else {
		stOutput, err := stsSess.GetSessionToken(&sts.GetSessionTokenInput{
			TokenCode:       &codeStr,
			SerialNumber:    &mfaDevice,
			DurationSeconds: &params.Duration,
		})
		errCheck(err)

		if verbose {
			fmt.Println("")
			fmt.Println(fmt.Sprintf("aws_access_key_id: %s", *stOutput.Credentials.AccessKeyId))
			fmt.Println(fmt.Sprintf("aws_secret_access_key: %s", *stOutput.Credentials.SecretAccessKey))
			fmt.Println(fmt.Sprintf("aws_session_token: %s", *stOutput.Credentials.SessionToken))
			fmt.Println(fmt.Sprintf("expiration: %s", *stOutput.Credentials.Expiration))
		}
		newCred := &credentialInfo{
			AssumedRole:        "False",
			AwsAccessKeyID:     *stOutput.Credentials.AccessKeyId,
			AwsSecretAccessKey: *stOutput.Credentials.SecretAccessKey,
			AwsSecurityToken:   *stOutput.Credentials.SessionToken,
			AwsSessionToken:    *stOutput.Credentials.SessionToken,
			Region:             credInfo.Region,
			Expiration:         *stOutput.Credentials.Expiration,
		}

		newSection, err := awsCredsFile.NewSection(shortTermProfile)
		errCheck(err)

		newSection.ReflectFrom(newCred)

	}

	_ = saveAwsCredentialsFile(awsCredsFile, "")

	return "", nil
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.splicectl/config.yml)")
	rootCmd.Flags().String("profile", "", "specify the target profile to write the token to")
	rootCmd.Flags().Int64("duration", 3600, "specify the duration for the temporary access token")
	rootCmd.Flags().String("assume-role", "", "specify a role to assume")
	rootCmd.Flags().String("short-term-suffix", "", "specify the short term profile suffix")
	rootCmd.Flags().String("role-session-name", "", "specify the role session name")
	rootCmd.Flags().BoolP("force", "", false, "for an update even if the token has not expired")
	rootCmd.Flags().BoolP("verbose", "", false, "for an update even if the token has not expired")
	rootCmd.MarkFlagRequired("profile")

}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		if _, err := os.Stat(cfgFile); err != nil {
			if os.IsNotExist(err) {
				if os.Args[1] != "auth" {
					logrus.Info("Couldn't read the config file.  We require a session ID from the splicectl API.  Please run with 'auth'.")
					os.Exit(1)
				} else {
					createRestrictedConfigFile(cfgFile)
				}
			}
		}
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		directory := fmt.Sprintf("%s/%s", home, ".aws-mfa")
		if _, err := os.Stat(directory); err != nil {
			if os.IsNotExist(err) {
				os.Mkdir(directory, os.ModePerm)
			}
		}
		if stat, err := os.Stat(directory); err == nil && stat.IsDir() {
			configFile := fmt.Sprintf("%s/%s", home, ".aws-mfa/config.yml")
			createRestrictedConfigFile(configFile)
			viper.SetConfigFile(configFile)
		} else {
			logrus.Info("The ~/.aws-mfa path is a file and not a directory, please remove the .aws-mfa file.")
			os.Exit(1)
		}
	}

	// viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err != nil {
		// couldn't read the config file.
	}
}

func createRestrictedConfigFile(fileName string) {
	if _, err := os.Stat(fileName); err != nil {
		if os.IsNotExist(err) {
			file, ferr := os.Create(fileName)
			if ferr != nil {
				logrus.Info("Unable to create the configfile.")
				os.Exit(1)
			}
			if runtime.GOOS != "windows" {
				mode := int(0600)
				if cherr := file.Chmod(os.FileMode(mode)); cherr != nil {
					logrus.Info("Chmod for config file failed, please set the mode to 0600.")
				}
			}
		}
	}
}
