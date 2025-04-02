package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	credentials "cloud.google.com/go/iam/credentials/apiv1"
	"cloud.google.com/go/iam/credentials/apiv1/credentialspb"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/idtoken"
)

// Supported log levels
var logLevels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

// GCPTokenRetriever implements stscreds.IdentityTokenRetriever
type GCPTokenRetriever struct {
	audience            string
	serviceAccountEmail string // Optional: only needed for local ADC
}

// GetIdentityToken implements the required interface method
func (g *GCPTokenRetriever) GetIdentityToken() ([]byte, error) {
	ctx := context.Background()

	// Try direct method first
	token, err := g.getTokenDirectly(ctx)
	if err == nil {
		return token, nil
	}

	slog.Debug("Direct token retrieval failed, trying impersonation method", slog.Any("error", err))

	token, impersonationErr := g.getTokenViaImpersonation(ctx)
	if impersonationErr != nil {
		// Return a combined error that includes both failure methods
		return nil, fmt.Errorf("identity token retrieval failed: direct method: %w; impersonation method: %w",
			err, impersonationErr)
	}

	return token, nil
}

func (g *GCPTokenRetriever) getTokenDirectly(ctx context.Context) ([]byte, error) {
	tokenSource, err := idtoken.NewTokenSource(ctx, g.audience)
	if err != nil {
		return nil, fmt.Errorf("failed to create token source: %w", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token directly: %w", err)
	}

	slog.Debug("Retrieved token via direct method", slog.String("expires", token.Expiry.Format(time.RFC3339)))
	return []byte(token.AccessToken), nil
}

func (g *GCPTokenRetriever) getTokenViaImpersonation(ctx context.Context) ([]byte, error) {
	if g.serviceAccountEmail == "" {
		return nil, fmt.Errorf("no service account email provided for impersonation")
	}

	// Create a client for the IAM Credentials API
	client, err := credentials.NewIamCredentialsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM credentials client: %w", err)
	}
	defer client.Close()

	// Format the resource name for the service account
	name := fmt.Sprintf("projects/-/serviceAccounts/%s", g.serviceAccountEmail)

	// Request an ID token with the specified audience
	req := &credentialspb.GenerateIdTokenRequest{
		Name:         name,
		Audience:     g.audience,
		IncludeEmail: true,
	}

	resp, err := client.GenerateIdToken(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID token via impersonation: %w", err)
	}

	slog.Debug("Retrieved token via service account impersonation")
	return []byte(resp.Token), nil
}

// setupLogger configures the global slog logger with the specified log level
func setupLogger(levelStr string) error {
	level, ok := logLevels[levelStr]
	if !ok {
		// Default to info if an invalid level is provided
		level = slog.LevelInfo
		slog.Warn("Invalid log level specified, defaulting to 'info'", "specified", levelStr)
	}

	// Create a JSON handler with the specified level
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
		// Add any other handler options you need here
	})

	// Set the default logger
	slog.SetDefault(slog.New(handler))

	return nil
}

// createSESClient creates an SES client with auto-refreshing credentials
func createSESClient(roleARN, region string, tokenRetriever stscreds.IdentityTokenRetriever) (*sesv2.Client, error) {
	ctx := context.Background()

	// Load base AWS config with region
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Create WebIdentity credential provider with auto-refresh
	webIdentityProvider := stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, tokenRetriever, func(o *stscreds.WebIdentityRoleOptions) {
		o.RoleSessionName = fmt.Sprintf("gcp-federation-%d", time.Now().Unix())
	})

	// Create new AWS config with the web identity provider
	cfgWithCreds, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(webIdentityProvider),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load config with credentials: %w", err)
	}

	// Create and return SES client
	return sesv2.NewFromConfig(cfgWithCreds), nil
}

// sendEmail sends an email using the provided SES client
func sendEmail(sesClient *sesv2.Client, sourceARN, sender, recipient, subject string) {
	ctx := context.Background()

	htmlBody := "<h1>Amazon SES Test Email</h1><p>This email was sent using <strong>Amazon SES</strong> and the AWS SDK for Go.</p>"
	textBody := "Amazon SES Test Email\nThis email was sent using Amazon SES and the AWS SDK for Go."

	// Create email input
	input := &sesv2.SendEmailInput{
		FromEmailAddress: &sender,
		Destination: &types.Destination{
			ToAddresses: []string{recipient},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Body: &types.Body{
					Html: &types.Content{
						Data:    aws.String(htmlBody),
						Charset: aws.String("UTF-8"),
					},
					Text: &types.Content{
						Data:    aws.String(textBody),
						Charset: aws.String("UTF-8"),
					},
				},
				Subject: &types.Content{
					Data:    aws.String(subject),
					Charset: aws.String("UTF-8"),
				},
				// Optional headers
				Headers: []types.MessageHeader{},
			},
		},
	}

	if sourceARN != "" {
		input.FromEmailAddressIdentityArn = aws.String(sourceARN)
	}

	// Send the email
	result, err := sesClient.SendEmail(ctx, input)
	if err != nil {
		slog.Error("Failed to send email", slog.Any("error", err))
		return
	}

	slog.Info("Email sent successfully", slog.String("message_id", *result.MessageId))
}

// Function to help prepare AWS IAM Role Trust Policy Configuration

// decodeAndPrintToken decodes a JWT token without verification and prints its contents
func decodeAndPrintToken(tokenString string) (string, string, string, error) {
	var authorizedParty, audience, subject string

	// Parse without validating signature
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// We're not validating here, just decoding
		return nil, nil
	})

	// If parsing failed completely
	if token == nil {
		return "", "", "", fmt.Errorf("failed to parse token")
	}

	fmt.Println("\n--- Token Information (Decoded) ---")

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Print claims
		claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
		fmt.Println("Claims:", string(claimsJSON))

		// Extract and highlight key fields
		authorizedParty = fmt.Sprintf("%v", claims["azp"])
		audience = fmt.Sprintf("%v", claims["aud"])
		subject = fmt.Sprintf("%v", claims["sub"])

		fmt.Printf("\nKey Fields:\n")
		fmt.Printf("Issuer (iss): %v\n", claims["iss"])
		fmt.Printf("Authorized Party (azp): %v\n", authorizedParty)
		fmt.Printf("Audience (aud): %v\n", audience)
		fmt.Printf("Subject (sub): %v\n", subject)
		fmt.Printf("Expiration (exp): %v\n", claims["exp"])

	}

	// Get header
	headerJSON, _ := json.MarshalIndent(token.Header, "", "  ")
	fmt.Println("\nHeader:", string(headerJSON))

	// Get KID
	if kid, ok := token.Header["kid"].(string); ok {
		fmt.Printf("\nKey ID (kid): %s\n", kid)
	}

	fmt.Println("-----------------------------------------------")

	return authorizedParty, audience, subject, nil
}

// printTrustPolicyInstructions provides guidance for setting up the IAM role trust policy
func printTrustPolicyInstructions(authorizedParty, audience, subject string) {
	fmt.Println("\n=== AWS IAM Role Trust Policy Configuration ===")
	fmt.Println("\nbased on https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/")
	fmt.Println("\nPlease update your IAM role trust policy to include:")

	trustPolicy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "accounts.google.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "%s",
          "accounts.google.com:oaud": "%s",
          "accounts.google.com:sub": "%s"
        }
      }
    }
  ]
}`, authorizedParty, audience, subject)

	fmt.Println(trustPolicy)
	fmt.Println("=============================================")
}

func main() {
	// Define command-line flags
	audiencePtr := flag.String("audience", "", "Target audience for the GCP identity token, e.g. https://example.com")
	awsRolePtr := flag.String("role", "", "AWS IAM role ARN to assume, e.g. arn:aws:iam::123456789012:role/ExampleRole")
	awsRegionPtr := flag.String("region", "ap-northeast-1", "AWS region for API calls")
	senderPtr := flag.String("sender", "", "Email sender address e.g. no-replay@example.com")
	recipientPtr := flag.String("recipient", "success@simulator.amazonses.com", "Email recipient address")
	subjectPtr := flag.String("subject", "Test Email from Amazon SES using Go", "Email subject")
	sesSourceArnPtr := flag.String("ses-source-arn", "", "SES source ARN e.g. arn:aws:ses:us-west-2:123456789012:identity/example.com")
	serviceAccountPtr := flag.String("service-account", "", "Optional: Service account email for impersonation when using local ADC")
	logLevelPtr := flag.String("log-level", "info", "Log level: debug, info, warn, or error")
	showTokenPtr := flag.Bool("show-token", false, "Show the GCP identity token and exit")
	flag.Parse()

	// Get values from flags
	normalizedLogLevel := strings.ToLower(strings.TrimSpace(*logLevelPtr))
	audience := *audiencePtr
	awsRole := *awsRolePtr
	//	awsRegion := *awsRegionPtr
	showToken := *showTokenPtr

	// Set up slog
	if err := setupLogger(normalizedLogLevel); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set up logger: %v\n", err)
		os.Exit(1)
	}

	if audience == "" || awsRole == "" || *senderPtr == "" {
		slog.Error("Please provide an audience, AWS role ARN, and sender address")
		os.Exit(1)
	}

	// Create a token retriever
	tokenRetriever := &GCPTokenRetriever{
		audience:            *audiencePtr,
		serviceAccountEmail: *serviceAccountPtr,
	}
	if showToken {
		tokenBytes, err := tokenRetriever.GetIdentityToken()
		if err != nil {
			slog.Error("Failed to get GCP identity token", slog.Any("error", err))
			os.Exit(1)
		}
		token := string(tokenBytes)
		az, au, sub, err := decodeAndPrintToken(token)
		if err != nil {
			slog.Error("Failed to decode token", slog.Any("error", err))
			os.Exit(1)
		}
		printTrustPolicyInstructions(az, au, sub)
		os.Exit(0)
	}

	// Create AWS clients with auto-refreshing credentials
	sesClient, err := createSESClient(*awsRolePtr, *awsRegionPtr, tokenRetriever)
	if err != nil {
		slog.Error("Failed to create SES client", slog.Any("error", err))
		os.Exit(1)
	}

	// Send email using SES
	sendEmail(sesClient, *sesSourceArnPtr, *senderPtr, *recipientPtr, *subjectPtr)
}
