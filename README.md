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