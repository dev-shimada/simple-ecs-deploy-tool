use clap::{Parser, Subcommand};
use async_trait::async_trait;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_ecr::{Client as EcrSdkClient};
use aws_sdk_ecs::{Client as EcsSdkClient};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// ECSのデプロイ設定をチェックします
    Check {
        #[clap(long)]
        cluster: String,
        #[clap(long)]
        service: String,
        #[clap(long)]
        task_definition: String,
        #[clap(long)]
        repository_name: String,
    },
}

pub async fn run() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Check { cluster, service, task_definition, repository_name } => {
            let client = AwsSdkClient::new().await;
            check(&client, cluster, service, task_definition, repository_name, &mut std::io::stdout()).await.unwrap();
        }
    }
}

pub async fn check<T: AwsClient>(
    client: &T, 
    cluster: &str, 
    service: &str, 
    task_definition: &str, 
    repository_name: &str, 
    mut writer: impl std::io::Write
) -> Result<(), ()> {
    let image_digests = client.describe_images(repository_name).await?;
    let latest_image_digest = image_digests.first().unwrap();

    let task_definition_arn = client.describe_task_definition(task_definition).await?;
    let service_task_definition = client.describe_services(cluster, service).await?;

    if *latest_image_digest != service_task_definition {
        writeln!(writer, "Image digest mismatch:").unwrap();
        writeln!(writer, "  Latest: {}", latest_image_digest).unwrap();
        writeln!(writer, "  Service: {}", service_task_definition).unwrap();
    } else {
        writeln!(writer, "Image digest is up to date.").unwrap();
    }

    if task_definition_arn != service_task_definition {
        writeln!(writer, "Task definition mismatch:").unwrap();
        writeln!(writer, "  Latest: {}", task_definition_arn).unwrap();
        writeln!(writer, "  Service: {}", service_task_definition).unwrap();
    } else {
        writeln!(writer, "Task definition is up to date.").unwrap();
    }

    Ok(())
}

#[async_trait]
pub trait AwsClient: EcrClient + EcsClient {}

#[async_trait]
pub trait EcrClient {
    async fn describe_images(&self, repository_name: &str) -> Result<Vec<String>, ()>;
}

#[async_trait]
pub trait EcsClient {
    async fn describe_task_definition(&self, task_definition: &str) -> Result<String, ()>;
    async fn describe_services(&self, cluster: &str, service: &str) -> Result<String, ()>;
}

pub struct AwsSdkClient {
    ecr_client: EcrSdkClient,
    ecs_client: EcsSdkClient,
}

impl AwsSdkClient {
    pub async fn new() -> Self {
        let region_provider = RegionProviderChain::default_provider().or_else("ap-northeast-1");
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let ecr_client = EcrSdkClient::new(&config);
        let ecs_client = EcsSdkClient::new(&config);
        Self { ecr_client, ecs_client }
    }
}

#[async_trait]
impl EcrClient for AwsSdkClient {
    async fn describe_images(&self, repository_name: &str) -> Result<Vec<String>, ()> {
        let resp = self.ecr_client.describe_images().repository_name(repository_name).send().await;
        match resp {
            Ok(output) => {
                let mut image_details = output.image_details.unwrap_or_default();
                image_details.sort_by(|a, b| b.image_pushed_at.unwrap().cmp(&a.image_pushed_at.unwrap()));
                let digests = image_details.iter().take(5).map(|d| d.image_digest.as_ref().unwrap().to_string()).collect();
                Ok(digests)
            },
            Err(_) => Err(())
        }
    }
}

#[async_trait]
impl EcsClient for AwsSdkClient {
    async fn describe_task_definition(&self, task_definition: &str) -> Result<String, ()> {
        let resp = self.ecs_client.describe_task_definition().task_definition(task_definition).send().await;
        match resp {
            Ok(output) => {
                let arn = output.task_definition.unwrap().task_definition_arn.unwrap();
                Ok(arn)
            },
            Err(_) => Err(())
        }
    }

    async fn describe_services(&self, cluster: &str, service: &str) -> Result<String, ()> {
        let resp = self.ecs_client.describe_services().cluster(cluster).services(service).send().await;
        match resp {
            Ok(output) => {
                let service = output.services.unwrap_or_default().into_iter().next().unwrap();
                let task_definition = service.task_definition.unwrap();
                Ok(task_definition)
            },
            Err(_) => Err(())
        }
    }
}

impl AwsClient for AwsSdkClient {}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockAwsClient;

    #[async_trait]
    impl EcrClient for MockAwsClient {
        async fn describe_images(&self, _repository_name: &str) -> Result<Vec<String>, ()> {
            Ok(vec![
                "sha256:dummy_digest1".to_string(),
                "sha256:dummy_digest2".to_string(),
                "sha256:dummy_digest3".to_string(),
                "sha256:dummy_digest4".to_string(),
                "sha256:dummy_digest5".to_string(),
            ])
        }
    }

    #[async_trait]
    impl EcsClient for MockAwsClient {
        async fn describe_task_definition(&self, _task_definition: &str) -> Result<String, ()> {
            Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:2".to_string())
        }

        async fn describe_services(&self, _cluster: &str, _service: &str) -> Result<String, ()> {
            Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1".to_string())
        }
    }

    impl AwsClient for MockAwsClient {}

    #[tokio::test]
    async fn test_get_latest_images_from_ecr() {
        let mock_aws_client = MockAwsClient;
        let images = mock_aws_client.describe_images("dummy-repo").await.unwrap();
        assert_eq!(images.len(), 5);
    }

    #[tokio::test]
    async fn test_get_latest_task_definition() {
        let mock_aws_client = MockAwsClient;
        let task_def = mock_aws_client.describe_task_definition("dummy--def").await.unwrap();
        assert_eq!(task_def, "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:2");
    }

    #[tokio::test]
    async fn check_subcommand_runs() {
        let mock_aws_client = MockAwsClient;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", "dummy-task-def", "dummy-repo", &mut writer).await;
        assert!(result.is_ok());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("Image digest mismatch:"));
        assert!(output.contains("  Latest: sha256:dummy_digest1"));
        assert!(output.contains("  Service: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1"));
        assert!(output.contains("Task definition mismatch:"));
        assert!(output.contains("  Latest: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:2"));
        assert!(output.contains("  Service: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1"));
    }
}