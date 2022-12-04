import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';

import { Construct } from 'constructs';

export interface AwsKmsCaRootCertProps {
    key: kms.IKey,
    lambdaZipFilePath: string,
}

/**
 * An AWS CDK Construct that defines an AWS CloudFormation Custom Resource
 * Provider that uses the provided KMS CMK to self-sign an X.509 Root
 * certificate.
 */
export class AwsKmsCaRootCert extends Construct {
    constructor(scope: Construct, id: string, props: AwsKmsCaRootCertProps) {
        super(scope, id);

        const lambdaExecRole = new iam.Role(this,`ExecRole`, {
                assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
                description: `lambda execution role for ${id}`,
            }
        );     

//        const kmsPolicy = new iam.PolicyStatement({
//            actions:['kms:GetPublicKey', 'kms:Sign', 'kms:UpdateKeyDescription', 'kms:DescribeKey'],
//            resources: [ props.key.keyArn],
//        });

        lambdaExecRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'));
//        lambdaExecRole.addToPolicy(kmsPolicy);

        props.key.grant(lambdaExecRole, 'kms:GetPublicKey', 'kms:Sign', 'kms:UpdateKeyDescription', 'kms:DescribeKey');

        const customResourceHandler = new lambda.Function(this, `CustResFn`, {
            architecture: lambda.Architecture.ARM_64,
            memorySize: 256,
            tracing: lambda.Tracing.ACTIVE,
            timeout: cdk.Duration.seconds(60),
//            logRetention: logs.RetentionDays.ONE_WEEK,
            runtime: lambda.Runtime.PROVIDED_AL2,
            handler: 'not.used', // name.othername pattern required, else will cause runtime cfn error with obscure error
            role: lambdaExecRole,
            code: lambda.Code.fromAsset(props.lambdaZipFilePath),
            environment: {
                RUST_LOG: 'info',
            }
        });

        const customResource = new cdk.CustomResource(this, `CustRes`, {
            serviceToken: customResourceHandler.functionArn,
            properties: {
                'kms_ca_root_arn': props.key.keyArn, // ensure key name matches name in aws-kms-ca-root-cfn-cr-lambda
            }
        });
    }
}
