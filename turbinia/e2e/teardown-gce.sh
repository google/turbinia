!/bin/bash
# This script will cleanup and teardown the Turbinia Terraform setup after
# the e2e test is finished
echo "Tear down Terraform Turbinia infrastructure."

export DEVSHELL_PROJECT_ID=`gcloud config list --format 'value(core.project)'`
cd ./forseti-security/contrib/incident-response/infrastructure/
terraform destroy --target=module.turbinia -var gcp_project=$DEVSHELL_PROJECT_ID -auto-approve

# Remove test and evidence disks (test-disk2 and evidence* disks)
ZONE="us-central1-a"
gcloud -q compute disks delete test-disk2 --zone=$ZONE
for d in `gcloud compute disks list --uri`
do
  DISK=`echo $d | cut -d '/' -f 11`
  ZONE=`echo $d | cut -d '/' -f 9`
  if [[ $DISK == "evidence"* ]]
  then
    echo "Deleting $DISK in $ZONE"
    gcloud -q compute disks delete $DISK --zone=$ZONE
  fi
done

# Remove terraform service account
gcloud -q iam service-accounts delete terraform@$DEVSHELL_PROJECT_ID.iam.gserviceaccount.com
