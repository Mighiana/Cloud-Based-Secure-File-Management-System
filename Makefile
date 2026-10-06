# Offline quality gate: no AWS account or credentials are needed for any target.
#   make bootstrap   install pinned, checksum-verified tools into .tools/
#   make init        terraform init (no backend), tflint plugins, dotnet restore
#   make check       everything CI runs
.PHONY: bootstrap init init-tf check fmt-check validate tf-test tflint checkov shellcheck dotnet-test lambda-test up down

TOOLS := $(CURDIR)/.tools
BIN   := $(TOOLS)/bin
PY    := $(TOOLS)/venv/bin/python
TF    := $(BIN)/terraform
TF_DIR := deploy/aws
DOTNET ?= dotnet

bootstrap:
	./scripts/bootstrap-tools.sh

init: init-tf
	$(DOTNET) restore SecureFileUploadPortal.sln

init-tf:
	$(TF) -chdir=$(TF_DIR) init -backend=false -input=false
	cd $(TF_DIR) && $(BIN)/tflint --init

check: fmt-check validate tf-test tflint checkov shellcheck dotnet-test lambda-test
	@echo "all checks passed"

fmt-check:
	$(TF) -chdir=$(TF_DIR) fmt -check -recursive

validate:
	$(TF) -chdir=$(TF_DIR) validate

tf-test:
	$(TF) -chdir=$(TF_DIR) test

tflint:
	cd $(TF_DIR) && $(BIN)/tflint --format compact

checkov:
	$(TOOLS)/checkov-venv/bin/checkov -d $(TF_DIR) --framework terraform --quiet --compact

shellcheck:
	$(BIN)/shellcheck deploy/localstack/*.sh scripts/*.sh

dotnet-test:
	$(DOTNET) build SecureFileUploadPortal.sln -c Release -warnaserror
	$(DOTNET) test SecureFileUploadPortal.sln --no-build -c Release

lambda-test:
	cd lambda/upload-scan && $(PY) -m pytest -q -p no:cacheprovider tests

up:
	docker compose up --build -d

down:
	docker compose down
