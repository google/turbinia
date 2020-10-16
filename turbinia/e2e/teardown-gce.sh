#/bin/bash
# This script will cleanup and teardown the Turbinia Terraform setup after
# the Turbinia e2e test is finished.
echo "Tear down Terraform Turbinia infrastructure."


if [ $# -ne  2 ]
then
  echo "Not enough arguments supplied, please provide the project and zone name."
  echo "$0 [PROJECT] [ZONE]"
  exit 1
fi

PROJECT="$1"
ZONE="$2"

SA_MEMBER="terraform@$PROJECT.iam.gserviceaccount.com"

echo "Destroying Terraform infrastructure..."
cd ./osdfir-infrastructure/
terraform destroy --target=module.turbinia -var gcp_project=$PROJECT -auto-approve

# Remove test and evidence disks (test-disk2 and evidence* disks)
echo "Deleting test and evidence disks..."
gcloud -q --project=$PROJECT compute disks delete test-disk2 --zone=$ZONE
for d in `gcloud compute disks list --uri`
do
  DISK=`echo $d | cut -d '/' -f 11`
  ZONE=`echo $d | cut -d '/' -f 9`
  if [[ $DISK == "evidence"* ]]
  then
    echo "Deleting $DISK in $ZONE"
    gcloud -q --project=$PROJECT compute disks delete $DISK --zone=$ZONE
  fi
done

# Remove IAM bindings and terraform service account
echo "Removing IAM bidings and service account..."
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/editor'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/compute.admin'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/cloudfunctions.admin'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/servicemanagement.admin'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/pubsub.admin'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/storage.admin'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/redis.admin'
gcloud -q --project=$PROJECT projects remove-iam-policy-binding $PROJECT --member=serviceAccount:$SA_MEMBER --role='roles/cloudsql.admin'
gcloud -q --project=$PROJECT iam service-accounts delete $SA_MEMBER
