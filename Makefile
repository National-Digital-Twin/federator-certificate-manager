SYSTEM_DIR        ?= ./credentials
BOOTSTRAP_MINUTES ?= 5
ROOT_CA_DIR       ?= ./ca

all : bootstrap-test-certs bootstrap-test-certs-clean create-empty-keystore
.PHONY : all

bootstrap-test-certs:
	./scripts/generate-bootstrap-cert.sh \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR)


bootstrap-test-certs-clean:
	./scripts/generate-bootstrap-cert.sh --clean \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR)

create-empty-keystore:
	./scripts/generate-bootstrap-cert.sh --clean --empty-keystore \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR)
