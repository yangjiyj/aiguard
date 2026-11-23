# JJDGuard 7B GPU Judge addon (judge-v4)

This addon packages the owned 7B semantic Judge, judge-v4 (Qwen2.5-7B-Instruct
fine-tuned by JJDGuard, merged and quantized to Q4_K_M). It is the model the
home reference deployment serves. The v5 LoRA candidate did not pass model
promotion and is not shipped; the addon rejects any LoRA input. It is
compatible with JJDGuard 2.6.12, 2.6.15, and 2.7.1. It does not install the gateway or
change any tenant policy. Build it only through
deploy/docker-compose/package-offline-bundle.sh with
BUNDLE_VARIANT=gpu-judge-7b-lora-addon (historical variant name) from a clean,
verified main revision.

## Build inputs

Set JUDGE_7B_BASE_INPUT to the canonical absolute path of
judge-v4-Q4_K_M.gguf. JUDGE_7B_LORA_INPUT must be unset. The packager rejects
any file whose filename, size, or SHA-256 differs from
owned-judge-7b-lora.lock.json (historical file name; schema
jjdguard-owned-judge-7b-lock/v2). The bundle contains the locked model file, a
pinned CUDA image, an image receipt, and a SHA-256 manifest.

## Customer host

Use a Linux amd64 host with an NVIDIA A100 (SM80) or H200 (SM90), a compatible
driver, Docker Engine, Compose v2, NVIDIA Container Toolkit, and OpenSSL. The
customer must provide enough GPU memory for the 7B model and the selected
parallel/context settings. Restrict the Judge listener to an internal IP and
allow only the gateway to reach it. The installer validates the GPU container
runtime, server TLS certificate, model response, and 1/2/4 concurrent probes.
Acceptance on the actual customer GPU remains mandatory.

## Install and connect

Extract the signed or checksum-verified bundle into a fixed directory on the
GPU host. Set JUDGE_BIND_IP to its real internal IPv4 address and run
bash install.sh. The installer writes a mode-0600 runtime.env with a generated
API key, creates a per-install TLS CA if none was provided, starts the
container, and saves acceptance-last.log. It does not print the API key.

Trust tls/ca.crt on the gateway host before routing traffic. In JJDGuard
semantic settings, configure a custom Judge with the HTTPS URL
https://<JUDGE_BIND_IP>:8094/v1/chat/completions and model name
qwen2.5-7b-judge-v4. Supply the API key from runtime.env through the
console's secret field. Validate a benign request and an attack request
through the real gateway. Keep the existing audit or block policy unless an
administrator explicitly changes it.

## Upgrading from 1.1.0 (v5 LoRA)

Install 1.2.0 into a new directory. Copy runtime.env and tls/ from the old
directory if you want to keep the same API key and certificate. Run
bash rollback.sh in the old directory, then bash install.sh in the new one.
Change the Judge model name in the console from qwen2.5-7b-judge-v5-full-lora
to qwen2.5-7b-judge-v4.

## Verify and rollback

Run bash verify.sh after installation and after host maintenance. The script
checks TLS, CUDA evidence, a semantic response, and concurrency 1/2/4.
To roll back, first restore the gateway's previous Judge URL, then run
bash rollback.sh. It stops only this addon and retains files for inspection.
