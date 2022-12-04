import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as AwsKmsCaRootCdk from '../lib/aws-kms-ca-root-cdk-stack';
import * as kms from 'aws-cdk-lib/aws-kms';
// kms.Key.fromKeyArn(scope, id+'Cmk', keyArn)
// arn:aws:kms:us-west-2:230966178829:key/1752dc6f-6187-4441-b1f9-813aa120a3a1
//
test('Certificate Created', () => {
    const app = new cdk.App();
// WHEN
    const stack = new AwsKmsCaRootCdk.AwsKmsCaRootCdkStack(app, 'CaRootCertStack', {
        keyArn: 'arn:aws:kms:us-west-2:230966178829:key/1752dc6f-6187-4441-b1f9-813aa120a3a1',
        lambdaZipFilePath: '../target/lambda/aws-kms-ca-root-cfn-cr-lambda/bootstrap.zip',
    });
// THEN
    const template = Template.fromStack(stack);

    console.log(template);
//    template.hasResourceProperties('AWS::SQS::Queue', {
//        VisibilityTimeout: 300
//    });
});
