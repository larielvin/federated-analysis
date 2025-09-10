.PHONY: train copy_train_output collector collector-stop collector-status \
		keys-generate check-recipients-hash keys-build keys-run wait-enclave \
		monitor-enclave console run-enclave party-verify party-rewrap \
		party-collect party-unarchive-keys party-copy-keys party-copy-model \
		server-copy-model party-send-data-to-server party-copy-decrypt-assets append-pcr0


DOCKER_COMPOSE = docker compose

data-generate:
	python3 ./data-generation/generate_synthetic_kenya.py --n 2500 --seed 123 --test_frac 0.2 --out ./fed-analysis-train/kenya_agri.csv

train:
	$(DOCKER_COMPOSE) -f ./fed-analysis-train/docker/docker-compose.yml run --rm --service-ports training-app

copy_train_output:
	cp ./fed-analysis-train/output/model/client.zip ./fed-analysis-keys/deployment_files/model

# -------------------------
# Keys / Enclave workflow
# -------------------------


OUTPUT_DIR    ?= ./fed-analysis-keys/output
COLLECTOR_PORT ?= 7002
COLLECTOR_PID  ?= .collector.pid
COLLECTOR_LOG  ?= $(OUTPUT_DIR)/collector.log
METRICS_FILE  ?= $(OUTPUT_DIR)/metrics.tsv
DOCKER_IMAGE_TAG ?= keys-app:latest
EIF ?= ./keys-app.eif

SHELL := /bin/bash
.ONESHELL:
OUT ?= $(OUTPUT_DIR)/bundle.env

RECIPIENTS_NAMES ?= government insurance processor bank agritech
RECIP_ENV ?= ./fed-analysis-keys/age_files/recipients/recipients.env
-include $(RECIP_ENV)
export RECIPIENTS_JSON_SHA256

# PCR0 := $(shell sudo nitro-cli describe-eif --eif-path ./keys-app.eif | jq -r '.Measurements.PCR0')

# write header if metrics file doesn’t exist
define WRITE_METRICS_HEADER
	@if [ ! -f "$(METRICS_FILE)" ]; then \
		mkdir -p "$(OUTPUT_DIR)"; \
		printf "ts\tdocker_build_s\tdocker_image_id\tdocker_image_mb\tenclave_build_s\teif_mb\tenclave_startup_s\tenclave_runtime_s\n" > "$(METRICS_FILE)"; \
	fi
endef

# portable "stat bytes" (GNU stat -> BSD/macOS stat)
define STAT_BYTES
stat -c %s "$(1)" 2>/dev/null || stat -f %z "$(1)" 2>/dev/null || echo 0
endef

collector:
	@mkdir -p $(OUTPUT_DIR)
	@if [ -f $(COLLECTOR_PID) ] && ps -p $$(cat $(COLLECTOR_PID)) >/dev/null 2>&1; then \
		echo "[collector] already running (pid $$(cat $(COLLECTOR_PID)))"; \
	else \
		nohup python3 -u ./fed-analysis-keys/collector.py \
			--port $(COLLECTOR_PORT) \
			--out  $(OUTPUT_DIR) \
			>/dev/null 2>&1 & \
		echo $$! > $(COLLECTOR_PID); \
		echo "[collector] pid $$! (port $(COLLECTOR_PORT), out $(OUTPUT_DIR), log: $(OUTPUT_DIR)/collector.log)"; \
	fi

collector-stop:
	@if [ -f .collector.pid ]; then kill $$(cat .collector.pid) || true; rm -f .collector.pid; fi

collector-status:
	@if [ -f $(COLLECTOR_PID) ] && ps -p $$(cat $(COLLECTOR_PID)) >/dev/null 2>&1; then \
		echo "[collector] running (pid $$(cat $(COLLECTOR_PID)))"; \
	else \
		echo "[collector] not running"; \
	fi

keys-generate:
	chmod +x ./fed-analysis-keys/generate_age_keys.sh
	./fed-analysis-keys/generate_age_keys.sh $(RECIPIENTS_NAMES)

check-recipients-hash:
ifeq ($(strip $(RECIPIENTS_JSON_SHA256)),)
	$(error RECIPIENTS_JSON_SHA256 is empty. Run ./generate_age_keys.sh first)
endif

# -------------------- Build + measure --------------------

keys-build: check-recipients-hash
	@$(WRITE_METRICS_HEADER)
	@TS=$$(date -Iseconds); \
	echo "[build] docker build $(DOCKER_IMAGE_TAG) ..."; \
	START_D=$$(date +%s); \
	docker build --no-cache --build-arg RECIPIENTS_JSON_SHA256="$(RECIPIENTS_JSON_SHA256)" -t $(DOCKER_IMAGE_TAG) ./fed-analysis-keys ; \
	END_D=$$(date +%s); \
	DOCKER_SEC=$$((END_D-START_D)); \
	IMG_ID=$$(docker images --no-trunc --quiet $(DOCKER_IMAGE_TAG)); \
	IMG_BYTES=$$(docker image inspect $(DOCKER_IMAGE_TAG) --format '{{.Size}}'); \
	IMG_MB=$$(awk 'BEGIN {printf "%.2f", '"$$IMG_BYTES"'/1024/1024}'); \
	echo "[build] nitro-cli build-enclave -> $(EIF) ..."; \
	START_E=$$(date +%s); \
	sudo nitro-cli build-enclave --docker-uri $(DOCKER_IMAGE_TAG) --output-file $(EIF) >/dev/null; \
	END_E=$$(date +%s); \
	ENCLAVE_SEC=$$((END_E-START_E)); \
	EIF_BYTES=$$($(call STAT_BYTES,$(EIF))); \
	if [ "$$EIF_BYTES" -eq 0 ]; then \
		echo "[warn] could not determine EIF size"; \
		EIF_MB="0"; \
	else \
		EIF_MB=$$(awk 'BEGIN {printf "%.2f", '"$$EIF_BYTES"'/1024/1024}'); \
	fi; \
	printf "%s\t%s\t%s\t%s\t%s\t%s\t\t\n" "$$TS" "$$DOCKER_SEC" "$$IMG_ID" "$$IMG_MB" "$$ENCLAVE_SEC" "$$EIF_MB" >> "$(METRICS_FILE)"; \
	echo "[metrics] docker_build_s=$$DOCKER_SEC image_mb=$$IMG_MB enclave_build_s=$$ENCLAVE_SEC eif_mb=$$EIF_MB"

# -------------------- Run + measure startup --------------------
keys-run:
	@$(WRITE_METRICS_HEADER)
	@echo "[run] starting enclave from $(EIF) ..."
	@python3 -c "import time; print(time.time())" > .enclave_start_ts
	@sudo nitro-cli run-enclave --eif-path $(EIF) --cpu-count 4 --memory 9000 --enclave-cid 16 


# Wait until RUNNING; compute startup time; stash RUNNING timestamp for runtime calc.
wait-enclave:
	@echo "[wait] waiting for enclave to become RUNNING..."
	@i=0; \
	while [ $$i -lt 240 ]; do \
		ID=$$(sudo nitro-cli describe-enclaves | jq -r '.[] | select(.State=="RUNNING") | .EnclaveID' | head -n1); \
		if [ -n "$$ID" ]; then \
			echo $$ID > .enclave_id; \
			START=$$(cat .enclave_start_ts 2>/dev/null || echo 0); \
			NOW=$$(python3 -c "import time; print(time.time())"); \
			DELTA=$$(python3 -c "import sys; s=float(sys.argv[1]); n=float(sys.argv[2]); print(round(n-s,3))" $$START $$NOW); \
			echo $$NOW > .enclave_running_ts; \
			echo "[wait] enclave $$ID is RUNNING (startup_s=$$DELTA)"; \
			exit 0; \
		fi; \
		i=$$((i+1)); \
		sleep 1; \
	done; \
	echo "[wait] timed out waiting for enclave"; exit 1



# Monitor until enclave exits; compute RUNNING duration.
monitor-enclave:
	@ID=$$(cat .enclave_id 2>/dev/null || echo ""); \
	if [ -z "$$ID" ]; then \
		ID=$$(sudo nitro-cli describe-enclaves | jq -r '.[] | select(.State=="RUNNING") | .EnclaveID' | head -n1); \
	fi; \
	if [ -z "$$ID" ]; then echo "[monitor] no RUNNING enclave to monitor"; exit 1; fi; \
	RUN_TS=$$(cat .enclave_running_ts 2>/dev/null || python3 -c "import time; print(time.time())"); \
	echo "[monitor] tracking enclave $$ID RUNNING duration..."; \
	while true; do \
		STATE=$$(sudo nitro-cli describe-enclaves | jq -r '.[] | select(.EnclaveID=="'$$ID'") | .State' | head -n1); \
		if [ "$$STATE" != "RUNNING" ] || [ -z "$$STATE" ]; then \
			END=$$(python3 -c "import time; print(time.time())"); \
			RUNTIME=$$(python3 -c "import sys; s=float(sys.argv[1]); e=float(sys.argv[2]); print(round(e-s,3))" $$RUN_TS $$END); \
			echo "[monitor] enclave $$ID exited (runtime_s=$$RUNTIME)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done


# Attach to stdout/stderr of the running enclave (Ctrl-] to detach)
console: wait-enclave
	@ID=$$(cat .enclave_id 2>/dev/null || true); \
	if [ -z "$$ID" ]; then \
		ID=$$(sudo nitro-cli describe-enclaves \
			| jq -r '.[] | select(.State=="RUNNING") | .EnclaveID' | head -n1); \
	fi; \
	if [ -z "$$ID" ]; then echo "[console] no RUNNING enclave found"; exit 1; fi; \
	echo "[console] attaching to $$ID (Ctrl-] to exit)"; \
	sudo nitro-cli console --enclave-id $$ID

run-enclave: collector keys-run wait-enclave monitor-enclave

append-pcr0:
	@set -euo pipefail
	mkdir -p "$(dir $(OUT))"
	touch "$(OUT)"
	PCR0="$$( \
	  (nitro-cli describe-eif --eif-path "$(EIF)" 2>/dev/null || sudo nitro-cli describe-eif --eif-path "$(EIF)" 2>/dev/null) \
	    | jq -r '.Measurements.PCR0' 2>/dev/null \
	  || eif_dump --json "$(EIF)" 2>/dev/null | jq -r '.Measurements.PCR0' 2>/dev/null \
	  || eif_dump "$(EIF)" 2>/dev/null | grep -Eo 'PCR0[:=][[:space:]]*[0-9a-fA-F]+' | grep -Eo '[0-9a-fA-F]+' | head -n1 \
	)"
	if [ -z "$$PCR0" ]; then echo "Failed to obtain PCR0" >&2; exit 1; fi
	# Overwrite PCR0 if exists, else append; keep other lines unchanged
	awk -v val="$$PCR0" 'BEGIN{found=0} \
	    /^PCR0=/{print "PCR0=" val; found=1; next} \
	    {print} \
	    END{if(!found) print "PCR0=" val}' "$(OUT)" > "$(OUT).tmp"
	mv "$(OUT).tmp" "$(OUT)"
	echo "Set PCR0=$$PCR0 in $(OUT)"

party-download:
	python3 ./fed-analysis-keys/download.py --out ./fed-analysis-keys/download/

party-verify:
	python3 ./fed-analysis-keys/verify_artifacts.py 
# 		--pcr0-allow $(PCR0)


party-rewrap:
	python3 ./fed-analysis-keys/wrap_share_for_all.py \
		--recipients ./fed-analysis-keys/age_files/recipients/recipients.json \
		--my-id government \
		--my-age-key ./fed-analysis-keys/age_files/.secrets/government.key \
		--in-share-age ./fed-analysis-keys/output/shares/share_government.age \
		--out-dir ./fed-analysis-keys/rewrapped \
		--context "$(jq -r '.ciphertext_sha256' ./fed-analysis-keys/output/receipt.v1.json)"
	python3 ./fed-analysis-keys/wrap_share_for_all.py \
		--recipients ./fed-analysis-keys/age_files/recipients/recipients.json \
		--my-id insurance \
		--my-age-key ./fed-analysis-keys/age_files/.secrets/insurance.key \
		--in-share-age ./fed-analysis-keys/output/shares/share_insurance.age \
		--out-dir ./fed-analysis-keys/rewrapped \
		--context "$(jq -r '.ciphertext_sha256' ./fed-analysis-keys/output/receipt.v1.json)"
	python3 ./fed-analysis-keys/wrap_share_for_all.py \
		--recipients ./fed-analysis-keys/age_files/recipients/recipients.json \
		--my-id processor \
		--my-age-key ./fed-analysis-keys/age_files/.secrets/processor.key \
		--in-share-age ./fed-analysis-keys/output/shares/share_processor.age \
		--out-dir ./fed-analysis-keys/rewrapped \
		--context "$(jq -r '.ciphertext_sha256' ./fed-analysis-keys/output/receipt.v1.json)"
	python3 ./fed-analysis-keys/wrap_share_for_all.py \
		--recipients ./fed-analysis-keys/age_files/recipients/recipients.json \
		--my-id bank \
		--my-age-key ./fed-analysis-keys/age_files/.secrets/bank.key \
		--in-share-age ./fed-analysis-keys/output/shares/share_bank.age \
		--out-dir ./fed-analysis-keys/rewrapped \
		--context "$(jq -r '.ciphertext_sha256' ./fed-analysis-keys/output/receipt.v1.json)"
	python3 ./fed-analysis-keys/wrap_share_for_all.py \
		--recipients ./fed-analysis-keys/age_files/recipients/recipients.json \
		--my-id agritech \
		--my-age-key ./fed-analysis-keys/age_files/.secrets/agritech.key \
		--in-share-age ./fed-analysis-keys/output/shares/share_agritech.age \
		--out-dir ./fed-analysis-keys/rewrapped \
		--context "$(jq -r '.ciphertext_sha256' ./fed-analysis-keys/output/receipt.v1.json)"

party-collect:
	python3 ./fed-analysis-keys/collect_and_recover.py \
		--me government \
		--my-age-key ./fed-analysis-keys/age_files/.secrets/government.key \
		--in-dir ./fed-analysis-keys/rewrapped \
		--own-share-age ./fed-analysis-keys/output/shares/share_government.age \
		--manifest ./fed-analysis-keys/output/manifest.v1.json \
		--receipt ./fed-analysis-keys/output/receipt.v1.json \
		--out ./fed-analysis-keys/output/fhe_keys.recovered.tar.gz
# 	python3 ./fed-analysis-keys/collect_and_recover.py \
# 		--me insurance \
# 		--my-age-key ./fed-analysis-keys/age_files/.secrets/insurance.key \
# 		--in-dir ./fed-analysis-keys/rewrapped \
# 		--own-share-age ./fed-analysis-keys/output/shares/share_insurance.age \
# 		--manifest ./fed-analysis-keys/output/manifest.v1.json \
# 		--receipt ./fed-analysis-keys/output/receipt.v1.json \
# 		--out ./fed-analysis-keys/output/fhe_keys.recovered.tar.gz
# 	python3 ./fed-analysis-keys/collect_and_recover.py \
# 		--me processor \
# 		--my-age-key ./fed-analysis-keys/age_files/.secrets/processor.key \
# 		--in-dir ./fed-analysis-keys/rewrapped \
# 		--own-share-age ./fed-analysis-keys/output/shares/share_processor.age \
# 		--manifest ./fed-analysis-keys/output/manifest.v1.json \
# 		--receipt ./fed-analysis-keys/output/receipt.v1.json \
# 		--out ./fed-analysis-keys/output/fhe_keys.recovered.tar.gz
# 	python3 ./fed-analysis-keys/collect_and_recover.py \
# 		--me bank \
# 		--my-age-key ./fed-analysis-keys/age_files/.secrets/bank.key \
# 		--in-dir ./fed-analysis-keys/rewrapped \
# 		--own-share-age ./fed-analysis-keys/output/shares/share_bank.age \
# 		--manifest ./fed-analysis-keys/output/manifest.v1.json \
# 		--receipt ./fed-analysis-keys/output/receipt.v1.json \
# 		--out ./fed-analysis-keys/output/fhe_keys.recovered.tar.gz
# 	python3 ./fed-analysis-keys/collect_and_recover.py \
# 		--me agritech \
# 		--my-age-key ./fed-analysis-keys/age_files/.secrets/agritech.key \
# 		--in-dir ./fed-analysis-keys/rewrapped \
# 		--own-share-age ./fed-analysis-keys/output/shares/share_agritech.age \
# 		--manifest ./fed-analysis-keys/output/manifest.v1.json \
# 		--receipt ./fed-analysis-keys/output/receipt.v1.json \
# 		--out ./fed-analysis-keys/output/fhe_keys.recovered.tar.gz

party-unarchive-keys:
	tar -xzvf ./fed-analysis-keys/output/fhe_keys.recovered.tar.gz -C ./fed-analysis-keys
	tar -xzvf ./fed-analysis-keys/output/evaluation_keys.tar.gz -C ./fed-analysis-keys


party-copy-keys:
	cp -r ./fed-analysis-keys/.fhe_keys ./fed-analysis-data-encrypt
	cp -r ./fed-analysis-keys/evaluation_keys/* ./fed-analysis-data-encrypt/client_files

party-copy-model:
	rsync -av --exclude='server.zip' ./fed-analysis-train/output/model/ ./fed-analysis-data-encrypt/deployment_files/model/

party-encrypt-data:
	$(DOCKER_COMPOSE) -f ./fed-analysis-data-encrypt/docker/docker-compose.yml run --rm --service-ports encrypt-app

server-copy-model:
	cp ./fed-analysis-train/output/model/server.zip ./fed-analysis-server-inference/deployment_files/model/
	cp ./fed-analysis-train/output/model/report.json ./fed-analysis-server-inference/deployment_files/model/

party-send-data-to-server:
	rsync -av ./fed-analysis-data-encrypt/client_files/ ./fed-analysis-server-inference/server_files/

server-inference:
	$(DOCKER_COMPOSE) -f ./fed-analysis-server-inference/docker/docker-compose.yml run --rm --service-ports inference-app

party-copy-decrypt-assets:
	cp -r ./fed-analysis-data-encrypt/.fhe_keys ./fed-analysis-output-decrypt
	cp ./fed-analysis-data-encrypt/deployment_files/model/client.zip ./fed-analysis-output-decrypt/deployment_files/model/
	cp ./fed-analysis-server-inference/deployment_files/model/report.json ./fed-analysis-output-decrypt/deployment_files/model/
	rsync -av ./fed-analysis-server-inference/server_results/ ./fed-analysis-output-decrypt/server_results/

party-decrypt:
	$(DOCKER_COMPOSE) -f ./fed-analysis-output-decrypt/docker/docker-compose.yml run --rm --service-ports decrypt-app

decrypt-results:
	echo "Decrypted results are in ./fed-analysis-output-decrypt/server_results/"