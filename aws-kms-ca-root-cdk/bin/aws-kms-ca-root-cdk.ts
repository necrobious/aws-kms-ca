#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsKmsCaRootCdkStack } from '../lib/aws-kms-ca-root-cdk-stack';

const app = new cdk.App();
new AwsKmsCaRootCdkStack(app, 'CaRoot', {
  //keyArn: 'arn:aws:kms:us-west-2:230966178829:key/1752dc6f-6187-4441-b1f9-813aa120a3a1',
  //keyArn: 'arn:aws:kms:us-west-2:230966178829:alias/root-ca-key',
  keyArn: 'arn:aws:kms:us-west-2:230966178829:key/93c1b1e7-0f88-42f4-a009-cd4041eb87f3',
  lambdaZipFilePath: '../target/lambda/aws-kms-ca-root-cfn-cr-lambda/bootstrap.zip',
});

/* If you don't specify 'env', this stack will be environment-agnostic.
   * Account/Region-dependent features and context lookups will not work,
   * but a single synthesized template can be deployed anywhere. */

  /* Uncomment the next line to specialize this stack for the AWS Account
   * and Region that are implied by the current CLI configuration. */
  // env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: process.env.CDK_DEFAULT_REGION },

  /* Uncomment the next line if you know exactly what Account and Region you
   * want to deploy the stack to. */
  // env: { account: '123456789012', region: 'us-east-1' },

  /* For more information, see https://docs.aws.amazon.com/cdk/latest/guide/environments.html */
//});
