package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/idtoken"
)

// GCPTokenRetriever implements stscreds.IdentityTokenRetriever
type GCPTokenRetriever struct {
	audience string
}

// GetIdentityToken implements the required interface method
func (g *GCPTokenRetriever) GetIdentityToken() ([]byte, error) {
	fmt.Println("Getting new GCP identity token...")

	// Create a context (since our function doesn't accept one)
	ctx := context.Background()

	// Create a token source for the audience
	tokenSource, err := idtoken.NewTokenSource(ctx, g.audience)
	if err != nil {
		return nil, fmt.Errorf("failed to create token source: %w", err)
	}

	// Get the token
	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	fmt.Printf("Retrieved new token, expires: %s\n", token.Expiry.Format(time.RFC3339))

	// Return the token as []byte as required by the interface
	return []byte(token.AccessToken), nil
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
	debugPtr := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Get values from flags
	audience := *audiencePtr
	awsRole := *awsRolePtr
	//	awsRegion := *awsRegionPtr
	debug := *debugPtr

	if audience == "" || awsRole == "" || *senderPtr == "" {
		log.Fatal("Please provide an audience and AWS role ARN and sender address")
	}

	if debug {
		token, err := getGCPIdentityToken(audience)
		if err != nil {
			log.Fatalf("Failed to get GCP identity token: %v", err)
		}
		fmt.Printf("Successfully retrieved identity token: %s...\n", token[:30])
		az, au, sub, err := decodeAndPrintToken(token)
		if err != nil {
			fmt.Printf("Failed to decode token: %v\n", err)
		}
		printTrustPolicyInstructions(az, au, sub)
		os.Exit(0)
	}

	// Create a token retriever
	tokenRetriever := &GCPTokenRetriever{audience: *audiencePtr}

	// Create AWS clients with auto-refreshing credentials
	sesClient, err := createSESClient(*awsRolePtr, *awsRegionPtr, tokenRetriever)
	if err != nil {
		log.Fatalf("Failed to create SES client: %v", err)
	}

	// Send email using SES
	fmt.Println("Sending email via SES...")
	sendEmail(sesClient, *sesSourceArnPtr, *senderPtr, *recipientPtr, *subjectPtr)

}

// createSESClient creates an SES client with auto-refreshing credentials
func createSESClient(roleARN, region string, tokenRetriever stscreds.IdentityTokenRetriever) (*ses.Client, error) {
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
	return ses.NewFromConfig(cfgWithCreds), nil
}

// createGCPTokenProvider returns a function that obtains GCP tokens
func createGCPTokenProvider(audience string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		fmt.Println("Getting new GCP identity token...")

		// Create a token source for the audience
		tokenSource, err := idtoken.NewTokenSource(ctx, audience)
		if err != nil {
			return "", fmt.Errorf("failed to create token source: %w", err)
		}

		// Get the token
		token, err := tokenSource.Token()
		if err != nil {
			return "", fmt.Errorf("failed to get token: %w", err)
		}

		fmt.Printf("Retrieved new token, expires: %s\n", token.Expiry.Format(time.RFC3339))
		return token.AccessToken, nil
	}
}

// sendEmail sends an email using the provided SES client
func sendEmail(sesClient *ses.Client, sourceARN, sender, recipient, subject string) {
	ctx := context.Background()

	htmlBody := "<h1>Amazon SES Test Email</h1><p>This email was sent using <strong>Amazon SES</strong> and the AWS SDK for Go.</p>"
	textBody := "Amazon SES Test Email\nThis email was sent using Amazon SES and the AWS SDK for Go."

	// Create email input
	input := &ses.SendEmailInput{
		Source: aws.String(sender),
		Destination: &types.Destination{
			ToAddresses: []string{recipient},
		},
		Message: &types.Message{
			Subject: &types.Content{
				Data:    aws.String(subject),
				Charset: aws.String("UTF-8"),
			},
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
		},
	}

	if sourceARN != "" {
		input.SourceArn = aws.String(sourceARN)
	}

	// Send the email
	result, err := sesClient.SendEmail(ctx, input)
	if err != nil {
		fmt.Printf("Failed to send email: %v\n", err)
		return
	}

	fmt.Printf("\nEmail sent successfully! Message ID: %s\n", *result.MessageId)
}

// Function to help prepare AWS IAM Role Trust Policy Configuration

// getGCPIdentityToken retrieves a GCP identity token for the specified audience
func getGCPIdentityToken(audience string) (string, error) {
	ctx := context.Background()

	// Create a token source for the audience
	tokenSource, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		return "", fmt.Errorf("failed to create token source: %w", err)
	}

	// Get the token
	token, err := tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	// For idtoken.NewTokenSource, the token should be in AccessToken
	return token.AccessToken, nil
}

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
