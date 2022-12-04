import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { AwsKmsCaRootCert } from 'aws-kms-ca-root-cdk-cr-lambda';
import * as kms from 'aws-cdk-lib/aws-kms';
// kms.Key.fromKeyArn(scope, id+'Cmk', keyArn)
// arn:aws:kms:us-west-2:230966178829:key/1752dc6f-6187-4441-b1f9-813aa120a3a1
//

export interface AwsKmsCaRootCdkStackProps extends cdk.StackProps {
    keyArn: string,// use the key id, do not use an alias, IAM doesnt like having resources defined using key aliases
    lambdaZipFilePath: string,
}

export class AwsKmsCaRootCdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: AwsKmsCaRootCdkStackProps) {
    super(scope, id, props);
    const key = kms.Key.fromKeyArn(this, `RootCmk`, props.keyArn);
    const cert = new AwsKmsCaRootCert(this, `RootCert`, {
      key,
      lambdaZipFilePath: props.lambdaZipFilePath,
    });
  }
}
