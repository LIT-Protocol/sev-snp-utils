SEV_SNP_CACHE_PATH := /tmp/sev-snp-utilities-test

.PHONY: test
test:
	rm -rf ${SEV_SNP_CACHE_PATH}
	mkdir -p ${SEV_SNP_CACHE_PATH}
	#SEV_SNP_CACHE_PATH=${SEV_SNP_CACHE_PATH} cargo test -- --nocapture
	SEV_SNP_CACHE_PATH=${SEV_SNP_CACHE_PATH} cargo test
	rm -rf ${SEV_SNP_CACHE_PATH}

.PHONY: test-nopurge
test-nopurge:
	#SEV_SNP_CACHE_PATH=${SEV_SNP_CACHE_PATH} cargo test -- --nocapture
	SEV_SNP_CACHE_PATH=${SEV_SNP_CACHE_PATH} cargo test

