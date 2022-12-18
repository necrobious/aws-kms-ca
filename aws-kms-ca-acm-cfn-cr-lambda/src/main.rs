//mod pkey;
mod create;
use create::create;
use async_trait::async_trait;
use ring::rand::SystemRandom;
use aws_custom_resource_provider_events::{
    ResponseStatus,
    ProviderResponse,
    ProviderResponseBuilder,
};
use aws_custom_resource_provider_lambda::{
    custom_resource_handler,
    HandlerConfig,
    types::CreateEvent,
    types::UpdateEvent,
    types::DeleteEvent,
    types::Provider,
};

use lambda_runtime::{Error as LambdaError};
use serde_derive::{ Serialize, Deserialize };
use service_fn::service_fn;
use tracing::info;
use aws_sdk_kms as kms;
use aws_sdk_acm as acm; 

//--- Resource properties specific to our custom-resource implementation
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CreateResourceProperties {
    pub kms_ca_root_arn: String,
    pub domain_names: Vec<String>,
    pub signing_algorithm: String, // ECDSA_SHA_256 | ECDSA_SHA_384
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct UpdateResourceProperties {
    pub kms_ca_root_arn: String,
    pub domain_names: Vec<String>,
    pub signing_algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DeleteResourceProperties {
    pub kms_ca_root_arn: String,
    pub domain_names: Vec<String>,
    pub signing_algorithm: String,
}
//---

//--- our custom resource provider impl
#[derive(Clone, Debug)]
pub struct ProviderConfig {
    rnd: SystemRandom,
    kms: kms::Client,
    acm: acm::Client,
}

#[derive(Clone,Debug)]
struct KmsCaAcmDomainCertProvider {
    config: ProviderConfig,
}

impl KmsCaAcmDomainCertProvider {
    pub fn new(config: ProviderConfig) -> Self {
        KmsCaAcmDomainCertProvider {
            config: config,
        }
    }
}

#[async_trait]
impl Provider for KmsCaAcmDomainCertProvider {
    type Create = CreateEvent<CreateResourceProperties>;
    type Update = UpdateEvent<UpdateResourceProperties>;
    type Delete = DeleteEvent<DeleteResourceProperties>;
    async fn create(&self, create_event: Self::Create) -> ProviderResponse {
        info!("create event started");
        let event = create_event.0;
        info!("create event: {:?}", &event);
        match create(&self.config, &event).await {
            Ok(provider_response) => {
                info!("create event success: {:?}", &provider_response);
                provider_response
            },
            Err(provider_response) => {
                info!("create event failure: {:?}", &provider_response);
                provider_response
            },
        }
    }

    async fn update(&self, update_event: Self::Update) -> ProviderResponse {
        info!("update event started");
        let event = update_event.0;
        info!("update event: {:?}", &event);

        let provider_response = ProviderResponseBuilder::from_event(event)
            .status(ResponseStatus::Success)
            .reason("Ok".to_string())
            .build();
        info!("update event response: {:?}", &provider_response);
        provider_response
    }

    async fn delete(&self, delete_event: Self::Delete) -> ProviderResponse {
        info!("delete event started");
        let event = delete_event.0;
        info!("delete event: {:?}", &event);
        let provider_response = ProviderResponseBuilder::from_event(event)
            .status(ResponseStatus::Success)
            .reason("Ok".to_string())
            .build();
        info!("delete event response: {:?}", &provider_response);
        provider_response
    }
}
//---

#[tokio::main]
async fn main() -> Result<(), LambdaError> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .without_time() //disabled because CloudWatch will add ingest time.
        .init();

    info!("Lambda bootstrap invoked");

    let sysrand = SystemRandom::new();

    let aws_config = aws_config::from_env().load().await;
    let kms_client = kms::Client::new(&aws_config);
    let acm_client = acm::Client::new(&aws_config);

    let provider_config = ProviderConfig {
        rnd: sysrand,
        kms: kms_client,
        acm: acm_client,
    };

    // config aws-custom-resource-provider
    let handler_config = HandlerConfig::new(
        KmsCaAcmDomainCertProvider::new(provider_config)
    );

    lambda_runtime::run(service_fn(handler_config, custom_resource_handler)).await?;

    Ok(())
}
