# GuardDuty Processor Terraform Module

This module deploys the Cloud Security Suite GuardDuty Processor as an event-driven Lambda subscribed to all GuardDuty Finding events through EventBridge.

## Resources

- Optional GuardDuty detector creation, controlled by `enable_guardduty`
- EventBridge rule matching `source = aws.guardduty` and `detail-type = GuardDuty Finding`
- Python 3.11 Lambda function
- SNS topic and email subscription for human-review notifications
- CloudWatch log group with configurable retention
- Lambda execution role with enrichment permissions, SNS publish access, and remediation playbook permissions

## Safety Defaults

`auto_remediate` defaults to `false`, and `dry_run` defaults to `true`. With defaults, the function enriches and notifies but does not perform write actions.

## Package

From `infrastructure/`:

```bash
./modules/guardduty_processor/package.sh
```

The script creates `modules/guardduty_processor/guardduty_processor_lambda.zip`, which Terraform uploads to Lambda.

## Manual Test

After deployment, generate a sample GuardDuty finding:

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-types Recon:EC2/PortProbeUnprotectedPort
```

Then inspect the Lambda logs:

```bash
aws logs tail "/aws/lambda/$(terraform output -raw guardduty_processor_lambda_name)" --follow
```
