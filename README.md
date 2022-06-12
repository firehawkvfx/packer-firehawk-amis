# Packer Firehawk AMI's

This module should be implemented with the firehawk-codepipeline module to automate builds.  Bootstrapping the firehawk-codepipeline module in AWS cloud shell will setup a pipeline to automatically build AMI's when the repository is updated, or manually through the web AWS management console.

If commits are made to this module, on a git push event, AWS Codebuild will build all images.  It is possible to also abort the build and use the AWS CodePipeline project in the AWS console to build and deploy.  If all images exist, they will not be built again.

IMPORTANT: It is not supported to push to packer-firehawk-amis and to the firehawk project at the same time.  This would result in two builds occurring simultaneously and may result in terraform resource locks preventing infrastructure from being deployed.
If you do push packer-firehawk-amis project you must either abort the packer-firehawk-amis build or wait for it to finish before running a build on firehawk-codepipeline.

The firehawk-codepipeline will detect if all images already exist for the commit hash of this repository.  
- If they all exist, no build will be required and the existing images will be used in the next deployment step.
- If any images are missing, all images matching the commit hash will be deleted from your AWS account and a new build of all images will occur to ensure consistency.

# Firehawk Base AMI

The firehawk-base-ami module is intended to provide all base images including any yum/apt updates.  The purpose of this is
to avoid subsequent yum/apt updates where possible to ensure consistency, since updates can introduce instability.

Once a build of firehawk-base-ami's exist in your AWS account for any given commit hash, they will not be rebuilt again unless:
- The commit hash changes
- Any of the required bash images are missing.