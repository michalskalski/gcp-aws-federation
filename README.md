## AWS SES Sender with GCP Federation

An example of go utility for sending emails via Amazon SES using GCP identity federation for cross-cloud authentication.

### Overview

This tool demonstrates a cross-cloud authentication pattern where it:

- Obtains a Google Cloud Platform identity token
- Uses the token to assume an AWS IAM role through Web Identity Federation
- Sends emails via Amazon SES using the assumed role credentials

This approach could be useful for workloads running in GCP that need to access AWS services securely without storing long-term AWS credentials.

#### IAM Setup

- Create an AWS IAM role that trusts Google Cloud Platform as an identity provider
- Attach a policy to the role allowing `ses:SendEmail` permission
- Configure the trust relationship to accept tokens from your GCP project

More details can be found in this articles:

- https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/
- https://jpassing.com/2021/10/05/authenticating-to-aws-by-using-a-google-cloud-service-account-and-assumerolewithwebidentity/

Example policy

``` json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ses:SendEmail",
      "Resource": [
        "arn:aws:ses:REGION:ACCOUNT_ID:identity/YOUR-DOMAIN.com"
      ]
    }
  ]
}
```

`-debug` flag can be used to print GCP token details and suggested AWS IAM role trust policy.

#### Usage

For local use instead of using default application credentials, you can set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to the path of your GCP service account key file.
