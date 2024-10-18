# demo-java-sbom

Demo of Java SBOM verification for different JDK / JRE 

## Building

Build images:

```sh
make build
```

Push images:
```sh
make push
```

Generate SBOMs:
```sh
make sbom
```

## Checking SBOMs

Newer Java versions have a `jrt-fs` that contains information on the vendor:

```json
    {
      "id": "ade8b7bfaa7d1871",
      "name": "jrt-fs",
      "version": "17.0.13",
      "type": "java-archive",
      "foundBy": "java-archive-cataloger",
      "locations": [
        {
          "path": "/usr/lib/jvm/java-17-amazon-corretto/lib/jrt-fs.jar",
          "layerID": "sha256:e71d1c13c6c83d7462ac9547188722b5dbbbfdf6f108b27f675b4929b5cc9f0a",
          "accessPath": "/usr/lib/jvm/java-17-amazon-corretto/lib/jrt-fs.jar",
          "annotations": {
            "evidence": "primary"
          }
        }
      ],
      "licenses": [],
      "language": "java",
      "cpes": [ 
        // trimmed ..
      ],
      "purl": "pkg:maven/jrt-fs/jrt-fs@17.0.13",
      "metadataType": "java-archive",
      "metadata": {
        "virtualPath": "/usr/lib/jvm/java-17-amazon-corretto/lib/jrt-fs.jar",
        "manifest": {
          "main": [
            {
              "key": "Manifest-Version",
              "value": "1.0"
            },
            {
              "key": "Specification-Title",
              "value": "Java Platform API Specification"
            },
            {
              "key": "Specification-Version",
              "value": "17"
            },
            {
              "key": "Specification-Vendor",
              "value": "Oracle Corporation"
            },
            {
              "key": "Implementation-Title",
              "value": "Java Runtime Environment"
            },
            {
              "key": "Implementation-Version",
              "value": "17.0.13"
            },
            {
              "key": "Implementation-Vendor",
              "value": "Amazon.com Inc."
            },
            {
              "key": "Created-By",
              "value": "17.0.12 (Amazon.com Inc.)"
            }
          ]
        },

        // trimmed ...
      }
    }
```

## SBOM attestation and verification using Kyverno policy

To sign attestations, install Cosign and generate a public-private key pair.

```
cosign generate-key-pair
```
This will generate the `cosign.key` and `cosign.pub`

To sign attestations, use the cosign attest command. This command will sign your attestations and publish them to the OCI registry.

```
# ${IMAGE} is REPOSITORY/PATH/NAME:TAG
cosign attest --key cosign.key --predicate <file> --type <predicate type>  ${IMAGE} 

```

The following cosign command creates the in-toto format attestation and signs it with the specified credentials using the custom predicate type https://syft.org/BOM/v1:

```
cosign attest ghcr.io/nirmata/demo-java-sbom:ubuntujre7 --key cosign.key --predicate demo-java-sbom/sboms/ubuntujre7.json --type https://syft.org/BOM/v1
```

The policy below verifies the package urls of the sbom and blocks pods if any of the package urls match oracle.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: attest-sbom
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  failurePolicy: Fail
  rules:
    - name: attest
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "ghcr.io/nirmata*"
        attestations:
          - type: https://syft.org/BOM/v1
            attestors:
            - entries:
              - keys:
                  publicKeys: |-
                    -----BEGIN PUBLIC KEY-----
                    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBgIImyAQSO4AI36uPF0FOj133HPJ
                    COAbRQly2B64JDYc+OLhJPhJM8H2BNU5LFAh64Bt79QWKyKaH1vNZRGxUw==
                    -----END PUBLIC KEY-----
            conditions:
              - all:
                - key: "{{ regex_match('^.*oracle.*$', '{{ artifacts[].purl }}') }}"
                  operator: Equals
                  value: false
```
