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
    #[clap(long)]
    profile: Option<String>,
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
        task_definition: Option<String>,
        #[clap(long)]
        repository_name: Option<String>,
    },
}

pub async fn run() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Check { cluster, service, task_definition, repository_name } => {
            let client = AwsSdkClient::new(cli.profile.as_deref()).await;
            check(&client, cluster, service, task_definition.as_deref(), repository_name.as_deref(), &mut std::io::stdout()).await.unwrap();
        }
    }
}

pub async fn check<T: AwsClient>(
    client: &T, 
    cluster: &str, 
    service: &str, 
    task_definition: Option<&str>, 
    repository_name: Option<&str>, 
    mut writer: impl std::io::Write
) -> Result<(), ()> {
    let service_task_definition_arn = client.describe_services(cluster, service).await?;
    let service_image_uri = match client.get_task_definition_image(&service_task_definition_arn).await? {
        Some(uri) => uri,
        None => {
            writeln!(writer, "No image found in service task definition: {}", service_task_definition_arn).unwrap();
            return Err(());
        }
    };

    let repository_name = match repository_name {
        Some(name) => name.to_string(),
        None => match client.get_repository_name_from_image(&service_image_uri).await? {
            Some(name) => name,
            None => {
                writeln!(writer, "Could not get repository name from image URI: {}", service_image_uri).unwrap();
                return Err(());
            }
        },
    };

    let image_digests = client.describe_images(&repository_name).await?;
    let latest_image_digest = match image_digests.first() {
        Some(digest) => digest,
        None => {
            writeln!(writer, "No images found in ECR repository: {}", repository_name).unwrap();
            return Err(());
        }
    };

    if latest_image_digest != &service_image_uri {
        writeln!(writer, "Image digest mismatch:").unwrap();
        writeln!(writer, "  Latest ECR: {}", latest_image_digest).unwrap();
        writeln!(writer, "  Service image: {}", service_image_uri).unwrap();
    } else {
        writeln!(writer, "Image digest is up to date.").unwrap();
    }

    let task_definition = match task_definition {
        Some(def) => def.to_string(),
        None => client.get_task_definition_family_from_arn(&service_task_definition_arn).await?,
    };

    let latest_task_definition_arn = client.describe_task_definition(&task_definition).await?;
    if latest_task_definition_arn != service_task_definition_arn {
        writeln!(writer, "Task definition mismatch:").unwrap();
        writeln!(writer, "  Latest: {}", latest_task_definition_arn).unwrap();
        writeln!(writer, "  Service: {}", service_task_definition_arn).unwrap();
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
    async fn get_repository_name_from_image(&self, image_uri: &str) -> Result<Option<String>, ()>;
}

#[async_trait]
pub trait EcsClient {
    async fn describe_task_definition(&self, task_definition: &str) -> Result<String, ()>;
    async fn describe_services(&self, cluster: &str, service: &str) -> Result<String, ()>;
    async fn get_task_definition_image(&self, task_definition_arn: &str) -> Result<Option<String>, ()>;
    async fn get_task_definition_family_from_arn(&self, task_definition_arn: &str) -> Result<String, ()>;
}

pub struct AwsSdkClient {
    ecr_client: EcrSdkClient,
    ecs_client: EcsSdkClient,
}

impl AwsSdkClient {
    pub async fn new(profile: Option<&str>) -> Self {
        let region_provider = RegionProviderChain::default_provider().or_else("ap-northeast-1");
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider);
        
        if let Some(profile_name) = profile {
            config_loader = config_loader.profile_name(profile_name);
        }

        let config = config_loader.load().await;
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
                image_details.sort_by(|a, b| b.image_pushed_at.cmp(&a.image_pushed_at));
                let digests = image_details.iter().filter_map(|d| d.image_digest.as_ref().map(|s| s.to_string())).collect();
                Ok(digests)
            },
            Err(_) => Err(())
        }
    }

    async fn get_repository_name_from_image(&self, image_uri: &str) -> Result<Option<String>, ()> {
        let repo_name = image_uri.split('/').nth(1).and_then(|s| s.split('@').next()).map(|s| s.to_string());
        Ok(repo_name)
    }
}

#[async_trait]
impl EcsClient for AwsSdkClient {
    async fn describe_task_definition(&self, task_definition: &str) -> Result<String, ()> {
        let resp = self.ecs_client.describe_task_definition().task_definition(task_definition).send().await;
        match resp {
            Ok(output) => {
                let arn = output.task_definition.and_then(|td| td.task_definition_arn).unwrap_or_default();
                Ok(arn)
            },
            Err(_) => Err(())
        }
    }

    async fn describe_services(&self, cluster: &str, service: &str) -> Result<String, ()> {
        let resp = self.ecs_client.describe_services().cluster(cluster).services(service).send().await;
        match resp {
            Ok(output) => {
                let service = output.services.unwrap_or_default().into_iter().next();
                let task_definition = service.and_then(|s| s.task_definition).unwrap_or_default();
                Ok(task_definition)
            },
            Err(_) => Err(())
        }
    }

    async fn get_task_definition_image(&self, task_definition_arn: &str) -> Result<Option<String>, ()> {
        let resp = self.ecs_client.describe_task_definition().task_definition(task_definition_arn).send().await;
        match resp {
            Ok(output) => {
                let image = output.task_definition
                    .and_then(|td| td.container_definitions)
                    .and_then(|mut cds| cds.pop())
                    .and_then(|cd| cd.image);
                Ok(image)
            },
            Err(_) => Err(())
        }
    }

    async fn get_task_definition_family_from_arn(&self, task_definition_arn: &str) -> Result<String, ()> {
        let family = task_definition_arn.split('/').nth(1).and_then(|s| s.split(':').next()).map(|s| s.to_string());
        Ok(family.unwrap_or_default())
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

        async fn get_repository_name_from_image(&self, _image_uri: &str) -> Result<Option<String>, ()> {
            Ok(Some("dummy-repo".to_string()))
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

        async fn get_task_definition_image(&self, task_definition_arn: &str) -> Result<Option<String>, ()> {
            if task_definition_arn == "arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1" {
                Ok(Some("123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest_from_service".to_string()))
            } else {
                Ok(Some("123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest_from_latest_task_def".to_string()))
            }
        }

        async fn get_task_definition_family_from_arn(&self, _task_definition_arn: &str) -> Result<String, ()> {
            Ok("dummy-task-def".to_string())
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
    async fn check_subcommand_runs_with_mismatch() {
        let mock_aws_client = MockAwsClient;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", Some("dummy-task-def"), Some("dummy-repo"), &mut writer).await;
        assert!(result.is_ok());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("Image digest mismatch:"));
        assert!(output.contains("  Latest ECR: sha256:dummy_digest1"));
        assert!(output.contains("  Service image: 123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest_from_service"));
        assert!(output.contains("Task definition mismatch:"));
        assert!(output.contains("  Latest: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:2"));
        assert!(output.contains("  Service: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1"));
    }

    #[tokio::test]
    async fn check_subcommand_runs_with_match() {
        struct MockAwsClientMatch;

        #[async_trait]
        impl EcrClient for MockAwsClientMatch {
            async fn describe_images(&self, _repository_name: &str) -> Result<Vec<String>, ()> {
                Ok(vec!["123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest1".to_string()])
            }
            async fn get_repository_name_from_image(&self, _image_uri: &str) -> Result<Option<String>, ()> {
                unimplemented!()
            }
        }

        #[async_trait]
        impl EcsClient for MockAwsClientMatch {
            async fn describe_task_definition(&self, _task_definition: &str) -> Result<String, ()> {
                Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1".to_string())
            }

            async fn describe_services(&self, _cluster: &str, _service: &str) -> Result<String, ()> {
                Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1".to_string())
            }

            async fn get_task_definition_image(&self, _task_definition_arn: &str) -> Result<Option<String>, ()> {
                Ok(Some("123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest1".to_string()))
            }
            async fn get_task_definition_family_from_arn(&self, _task_definition_arn: &str) -> Result<String, ()> {
                unimplemented!()
            }
        }
        impl AwsClient for MockAwsClientMatch {}

        let mock_aws_client = MockAwsClientMatch;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", Some("dummy-task-def"), Some("dummy-repo"), &mut writer).await;
        assert!(result.is_ok());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("Image digest is up to date."));
        assert!(output.contains("Task definition is up to date."));
    }

    #[tokio::test]
    async fn check_subcommand_runs_with_no_image_in_ecr() {
        struct MockAwsClientNoEcrImage;

        #[async_trait]
        impl EcrClient for MockAwsClientNoEcrImage {
            async fn describe_images(&self, _repository_name: &str) -> Result<Vec<String>, ()> {
                Ok(vec![])
            }
            async fn get_repository_name_from_image(&self, _image_uri: &str) -> Result<Option<String>, ()> {
                Ok(Some("dummy-repo".to_string()))
            }
        }

        #[async_trait]
        impl EcsClient for MockAwsClientNoEcrImage {
            async fn describe_task_definition(&self, _task_definition: &str) -> Result<String, ()> {
                unimplemented!()
            }

            async fn describe_services(&self, _cluster: &str, _service: &str) -> Result<String, ()> {
                Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1".to_string())
            }

            async fn get_task_definition_image(&self, _task_definition_arn: &str) -> Result<Option<String>, ()> {
                Ok(Some("123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest1".to_string()))
            }
            async fn get_task_definition_family_from_arn(&self, _task_definition_arn: &str) -> Result<String, ()> {
                unimplemented!()
            }
        }
        impl AwsClient for MockAwsClientNoEcrImage {}

        let mock_aws_client = MockAwsClientNoEcrImage;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", Some("dummy-task-def"), Some("dummy-repo"), &mut writer).await;
        assert!(result.is_err());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("No images found in ECR repository: dummy-repo"));
    }

    #[tokio::test]
    async fn check_subcommand_runs_with_no_image_in_service() {
        struct MockAwsClientNoServiceImage;

        #[async_trait]
        impl EcrClient for MockAwsClientNoServiceImage {
            async fn describe_images(&self, _repository_name: &str) -> Result<Vec<String>, ()> {
                Ok(vec!["sha256:dummy_digest1".to_string()])
            }
            async fn get_repository_name_from_image(&self, _image_uri: &str) -> Result<Option<String>, ()> {
                unimplemented!()
            }
        }

        #[async_trait]
        impl EcsClient for MockAwsClientNoServiceImage {
            async fn describe_task_definition(&self, _task_definition: &str) -> Result<String, ()> {
                unimplemented!()
            }

            async fn describe_services(&self, _cluster: &str, _service: &str) -> Result<String, ()> {
                Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1".to_string())
            }

            async fn get_task_definition_image(&self, _task_definition_arn: &str) -> Result<Option<String>, ()> {
                Ok(None)
            }
            async fn get_task_definition_family_from_arn(&self, _task_definition_arn: &str) -> Result<String, ()> {
                unimplemented!()
            }
        }
        impl AwsClient for MockAwsClientNoServiceImage {}

        let mock_aws_client = MockAwsClientNoServiceImage;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", Some("dummy-task-def"), Some("dummy-repo"), &mut writer).await;
        assert!(result.is_err());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("No image found in service task definition: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1"));
    }

    #[tokio::test]
    async fn check_subcommand_runs_without_task_definition_and_repository_name() {
        let mock_aws_client = MockAwsClient;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", None, None, &mut writer).await;
        assert!(result.is_ok());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("Image digest mismatch:"));
        assert!(output.contains("  Latest ECR: sha256:dummy_digest1"));
        assert!(output.contains("  Service image: 123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/dummy-repo@sha256:dummy_digest_from_service"));
        assert!(output.contains("Task definition mismatch:"));
        assert!(output.contains("  Latest: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:2"));
        assert!(output.contains("  Service: arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1"));
    }

    #[tokio::test]
    async fn check_subcommand_runs_with_no_repository_name_from_image() {
        struct MockAwsClientNoRepoName;

        #[async_trait]
        impl EcrClient for MockAwsClientNoRepoName {
            async fn describe_images(&self, _repository_name: &str) -> Result<Vec<String>, ()> {
                unimplemented!()
            }
            async fn get_repository_name_from_image(&self, _image_uri: &str) -> Result<Option<String>, ()> {
                Ok(None)
            }
        }

        #[async_trait]
        impl EcsClient for MockAwsClientNoRepoName {
            async fn describe_task_definition(&self, _task_definition: &str) -> Result<String, ()> {
                unimplemented!()
            }

            async fn describe_services(&self, _cluster: &str, _service: &str) -> Result<String, ()> {
                Ok("arn:aws:ecs:ap-northeast-1:123456789012:task-definition/dummy-task-def:1".to_string())
            }

            async fn get_task_definition_image(&self, _task_definition_arn: &str) -> Result<Option<String>, ()> {
                Ok(Some("invalid-image-uri".to_string()))
            }
            async fn get_task_definition_family_from_arn(&self, _task_definition_arn: &str) -> Result<String, ()> {
                unimplemented!()
            }
        }
        impl AwsClient for MockAwsClientNoRepoName {}

        let mock_aws_client = MockAwsClientNoRepoName;
        let mut writer = Vec::new();
        let result = check(&mock_aws_client, "dummy-cluster", "dummy-service", None, None, &mut writer).await;
        assert!(result.is_err());
        let output = String::from_utf8(writer).unwrap();
        assert!(output.contains("Could not get repository name from image URI: invalid-image-uri"));
    }
}
