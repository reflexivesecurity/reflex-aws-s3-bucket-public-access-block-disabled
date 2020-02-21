# reflex-aws-detect-disable-pulic-access-block
A Reflex rule for detecting when an S3 bucket has its public access block removed.

## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
version: 0.1

providers:
  - aws

measures:
  - reflex-aws-detect-disable-pulic-access-block
```

or add it directly to your Terraform:  
```
...

module "reflex-aws-detect-disable-pulic-access-block" {
  source           = "github.com/cloudmitigator/reflex-aws-detect-disable-pulic-access-block"
  email            = "example@example.com"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-detect-disable-pulic-access-block/blob/master/LICENSE) 
