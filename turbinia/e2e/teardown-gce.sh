#/bin/bash
# This script will cleanup and teardown the Turbinia Terraform setup after
# the Turbinia e2e test is finished.
echo "Tear down Terraform Turbinia infrastructure."


if [ $# -ne  2 ]
then
  echo "Not enough arguments supplied, please provide project and zone."
  echo "$0 [PROJECT] [ZONE]"
  exit 1
fi

PROJECT="$1"
ZONE="$2"

SA_MEMBER="terraform@$PROJECT.iam.gserviceaccount.com"

cd ./osdfir-infrastructure/
terraform destroy --target=module.turbinia -var gcp_project=$PROJECT -auto-approve

# Remove test and evidence disks (test-disk2 and evidence* disks)
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

# TODO(rbdebeer) Debug and fix remove-iam-policy-binding calls.
# Remove IAM bindings and terraform service account
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/editor' --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/compute.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/cloudfunctions.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/servicemanagement.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/pubsub.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/storage.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/redis.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts remove-iam-policy-binding $SA_MEMBER --member=serviceAccount:$SA_MEMBER --role='roles/cloudsql.admin'  --all
# gcloud -q --project=$PROJECT iam service-accounts delete $SA_MEMBER
