package utils

const (
	EmailPrompt = "Enter your email address:"

	PasswordPrompt        = "Enter your password:"
	PasswordConfirmPrompt = "Confirm your password:"
	PasswordsDoesntMatch  = "passwords do not match"

	TwoFactorCodeDescription = "Two-factor authentication. Enter 6-digit code from the 2FA app to verify your identity."
	TwoFactorCodePrompt      = "Enter 2-factor code:"

	AccountSuccessfullyRegistered = "Your account was successfully registered and activated. Go ahead and log in to your account with your credentials."

	ConfirmationCodeDescription = "We've sent you an email with a verification code to your email address. Check your inbox for an email from Virgil Security and copy the verification code."
	ConfirmationCodePrompt      = "Verification Code:"

	LoginSuccess    = "Success! Logged in as"
	LogoutSuccess   = "Logged out"
	LogoutNotNeeded = "No need to log out, not logged in"

	AppKeyNamePrompt    = "Enter App Key name"
	AppKeyCreateWarning = "This secret is only shown ONCE. Make note of it and store it in a safe, secure location."
	AppKeyOutput        = "App Key:"

	AppKeyIDPrompt       = "Enter App Key ID"
	AppKeyDeleteSuccess  = "App Key has been successfully deleted."
	AppKeysNotCreatedYet = "There are no app keys created for application"

	ApiKeyNotFound = "Not found Api key with id:"

	SpecifyAppIDFlag     = "Please, specify app_id (flag --app_id)"
	SpecifyTokenNameFlag = "Please, specify token name (flag --name)"
	SpecifyAppTokenFlag  = "Please, specify app-token (flag --app-token)"

	AppTokenNamePrompt     = "Enter token name"
	AppTokenNotFound       = "token not found"
	AppTokenDeleteSuccess  = "delete ok."
	AppTokensNotCreatedYet = "There are no app keys created for application"

	ApplicationNamePrompt        = "Enter application name"
	ApplicationIDPrompt          = "Enter application id"
	ApplicationIDOutput          = "App ID:"
	ApplicationCreateSuccess     = "Application has been successfully created."
	ApplicationDeletePrompt      = "Are you sure, that you want to delete application"
	ApplicationDeleteSuccess     = "Application has been successfully deleted."
	ApplicationNotFound          = "not found Application with id"
	ApplicationsNotCreateYet     = "There are no applications created for the account"
	ApplicationUpdateSuccess     = "Application has been successfully updated."
	ApplicationSetContextSuccess = "Application context set ok"
	ApplicationWithNameNotFound  = "there is no app with name "

	CardIDPrompt            = "Enter card id"
	CardIdentityPrompt      = "Enter card identity"
	CardDeletePrompt        = "Are you sure, that you want to delete card"
	CardDeleteSuccess       = "Card delete ok."
	CardNotFound            = "not found card with id"
	CardForIdentityNotFound = "there are no cards found for identity: "

	ConfigurationFileNotSpecified = "configuration file isn't specified (use -c)"
	KeyFileNotSpecified           = "key file isn't specified (use -key)"
	InputFileNotSpecified         = "input file isn't specified (use -i)"
	SignatureFileNotSpecified     = "signature file isn't specified (use -s)"

	KMSKeyNamePrompt    = "Enter key name"
	KMSKeyCreateSuccess = "KMS Key Pair has been successfully created."
	KMSKeyAliasInvalid  = "invalid kms key pair alias"

	KMSUpdateTokenDeleteSuccess = "Update token successfully deleted."

	SCMSDCMCertificateNamePrompt     = "Enter dsm certificate name"
	SCMSDCMPublicKeyPrompt           = "Enter encrypt public key"
	SCMSDCMPublicKeyVerifyPrompt     = "Enter verify public key"
	SCMSDCMCertificatesNotCreatedYet = "There are no certs created for the application"

	SCMSDeviceNotYetRegistered = "There are no devices registered for the application"

	SCMSApplicationInitSuccess = "Application init ok."

	DecryptDataPrompt = "Enter data to decrypt"

	EncryptDataPrompt = "Enter data to encrypt"

	ExtractPubKeyParseFailed = "can't parse private key (may be key password required)"

	SignDataPrompt          = "Enter data to sign"
	SignCantParsePrivateKey = "can't parse private key (may be key password required)"

	UseInvalidNumberArguments = "Invalid number of arguments. Please, specify application name"
	UseApplicationWarning     = "All future commands without specifying app_id will be applied to current app"

	VerifySuccess = "Signature OK "
	VerifyFailed  = "signature is invalid"

	CantImportPrivateKey = "can't import private key"
	CantImportPublicKey  = "can't import public key"
)
