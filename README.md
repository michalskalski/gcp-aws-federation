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

Generation of the GCP OIDC ID Token have to be done within service account context.

##### Aplication Default Credentials (ADC)

To support generating [OIDC ID Token](https://cloud.google.com/iam/docs/create-short-lived-credentials-direct#sa-credentials-oidc) with Local Application Default Credentials (ADC) it have to be initialized with [service account impersonation](https://cloud.google.com/docs/authentication/set-up-adc-local-dev-environment#service-account):

```console
$ gcloud auth application-default login --impersonate-service-account SERVICE_ACCT_EMAIL
```

and on the target service account following permissions have to be granted:

```console
$ gcloud iam service-accounts add-iam-policy-binding \
    SERVICE_ACCT_EMAIL \
    --member="serviceAccount:SERVICE_ACCT_EMAIL" \
    --role="roles/iam.serviceAccountTokenCreator"

$ gcloud iam service-accounts add-iam-policy-binding \
    SERVICE_ACCT_EMAIL \
    --member="serviceAccount:SERVICE_ACCT_EMAIL" \
    --role="roles/iam.serviceAccountOpenIDTokenCreator"

$ gcloud iam service-accounts add-iam-policy-binding \
    SERVICE_ACCT_EMAIL \
    --member="user:your-user@your-domain.com" \
    --role="roles/iam.serviceAccountTokenCreator"
```

##### Accept service account reference

You can use `-service-account` flag of this tool and point to the service account on which you have following permissions granted:

```console
$ gcloud iam service-accounts add-iam-policy-binding \
    sa-name@project-name.iam.gserviceaccount.com \
    --member="user:your-user@your-domain.com" \
    --role="roles/iam.serviceAccountOpenIdTokenCreator"
```

##### Service Account Key File

Use `GOOGLE_APPLICATION_CREDENTIALS` environment variable set to the path of the GCP [service account key file](https://cloud.google.com/iam/docs/keys-create-delete).
