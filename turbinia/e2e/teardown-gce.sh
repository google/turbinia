!/bin/bash
# This script will cleanup and teardown the Turbinia Terraform setup after
# the e2e test is finished
echo "Tear down Terraform Turbinia infrastructure."

export DEVSHELL_PROJECT_ID=`gcloud config list --format 'value(core.project)'`
cd ./forseti-security/contrib/incident-response/infrastructure/
terraform destroy --target=module.turbinia -var gcp_project=$DEVSHELL_PROJECT_ID -auto-approve
