SYSTEM_DIR        ?= /home/vagrant/test-secrets
BOOTSTRAP_MINUTES ?= 5
ROOT_CA_DIR       ?= /home/vagrant/test-secrets
KEYSTORE_PASS     ?= changeit
TRUSTSTORE_PASS   ?= changeit

all : bootstrap-test-certs bootstrap-test-certs-clean create-empty-keystore
.PHONY : all

bootstrap-test-certs:
	./scripts/generate-bootstrap-cert.sh \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR) \
	  $(KEYSTORE_PASS) \
	  $(TRUSTSTORE_PASS)


bootstrap-test-certs-clean:
	./scripts/generate-bootstrap-cert.sh --clean \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR) \
	  $(KEYSTORE_PASS) \
	  $(TRUSTSTORE_PASS)

create-empty-keystore:
	./scripts/generate-bootstrap-cert.sh --clean --empty-keystore \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR) \
	  $(KEYSTORE_PASS) \
	  $(TRUSTSTORE_PASS)
