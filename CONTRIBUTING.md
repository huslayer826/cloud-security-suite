# Contributing

Thanks for improving the Cloud Security Suite. This project uses small, reviewable pull requests and CI checks for tests, linting, Terraform validation, and security scanning.

## Development Workflow

1. Fork the repository.
2. Create a branch from `main`.
3. Make focused changes with tests and documentation when behavior changes.
4. Open a pull request and wait for CI to pass before requesting review.

## Branch Names

Use short branch names with one of these prefixes:

- `feat/` for new features
- `fix/` for bug fixes
- `docs/` for documentation-only changes
- `ci/` for workflow and automation changes
- `chore/` for maintenance

## Commit Messages

Use Conventional Commits:

```text
feat(iam-auditor): add access key rotation check
fix(cloudtrail): handle gzipped sample logs
docs(infra): document remote state setup
ci: add terraform validation workflow
```

## Run Tests Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest --cov=shared --cov=tools --cov-report=term --cov-fail-under=80 -v
ruff check .
mypy shared/
mypy tools/ \
  --ignore-missing-imports \
  --allow-untyped-defs \
  --allow-incomplete-defs \
  --disable-error-code attr-defined \
  --disable-error-code no-any-return \
  --disable-error-code type-arg \
  --disable-error-code arg-type \
  --disable-error-code misc
```

## Terraform Validation

Package Lambda artifacts before validation because Terraform references the generated zip files:

```bash
cd infrastructure
./modules/iam_auditor/package.sh
./modules/guardduty_processor/package.sh
./modules/cloudtrail_analyzer/package.sh
terraform fmt -recursive
terraform init -backend=false
terraform validate
```

The real `terraform.tfvars` file is gitignored. Use `terraform.tfvars.example` as the starting point for local testing.
