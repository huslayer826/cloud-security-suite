# Contributing

Thanks for improving the Cloud Security Suite. Keep pull requests small, focused, and easy to review.

## Workflow

1. Fork the repository.
2. Create a branch from `main` using `feat/`, `fix/`, `docs/`, `ci/`, or `chore/`.
3. Use Conventional Commits, such as `feat(iam-auditor): add policy check`.
4. Add or update tests and docs when behavior changes.
5. Open a pull request and wait for CI to pass.

## Local Checks

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest --cov=shared --cov=tools --cov-report=term --cov-fail-under=80 -v
ruff check .
mypy shared/
```

## Terraform Checks

Package Lambda artifacts before validating Terraform:

```bash
cd infrastructure
./modules/iam_auditor/package.sh
./modules/guardduty_processor/package.sh
./modules/cloudtrail_analyzer/package.sh
terraform fmt -recursive
terraform init -backend=false
terraform validate
```
