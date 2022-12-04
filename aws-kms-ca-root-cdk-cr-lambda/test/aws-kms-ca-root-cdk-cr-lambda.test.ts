import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { AwsKmsCaRootCert } from '../lib/index';

// example test. To run these tests, uncomment this file along with the
// example resource in lib/index.ts
test('CA Root Certificate Custom Resource Created', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, "TestStack");
    const expectedArn = 'arn:aws:kms:us-west-2:230966178829:alias/root-ca-key-test';
    const expectedZipPath = '../target/lambda/aws-kms-ca-root-cfn-cr-lambda/bootstrap.zip';

    const key = kms.Key.fromKeyArn(stack,'CARootKey', expectedArn);
//   // WHEN
    new AwsKmsCaRootCert(stack, 'CaRootCertConstruct', {
        key,
        lambdaZipFilePath: expectedZipPath,
    });

//   // THEN
    const template = Template.fromStack(stack);

    template.hasResourceProperties('AWS::IAM::Role',
        Match.objectLike({
            AssumeRolePolicyDocument: {
                Version: "2012-10-17",
                Statement: [
                    {
                        Action: "sts:AssumeRole",
                        Effect: "Allow",
                        Principal: {
                            Service: "lambda.amazonaws.com",
                        },
                    },
                ],
            },
            ManagedPolicyArns: [
                {
                    "Fn::Join": [
                        "",
                        [
                            "arn:",
                            {
                                "Ref": "AWS::Partition"
                            },
                            ":iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        ]
                    ]
                }
            ]
        })
    );
/*
    template.hasResourceProperties('AWS::IAM::Policy', { 
        PolicyDocument: Match.objectEquals({
            "Statement": [
              {
                "Action": [
                  "kms:GetPublicKey",
                  "kms:Sign",
                  "kms:UpdateKeyDescription"
                ],
                "Effect": "Allow",
                "Resource": "arn:aws:kms:us-west-2:230966178829:alias/root-ca-key-test"
              } 
            ]
        })
    });
*/
    template.hasResourceProperties('AWS::Lambda::Function', {
        Architectures: ['arm64'], 
        Handler: 'not.used',
        Runtime: 'provided.al2',  
    });
    template.hasResourceProperties('AWS::CloudFormation::CustomResource', {
        ServiceToken: Match.anyValue(), 
        kms_ca_root_arn: expectedArn, 
    });
});
