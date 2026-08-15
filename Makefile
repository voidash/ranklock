.PHONY: test critical results reproduce v0241 v025 release clean

test:
	PYTHONPATH=src python scripts/run_test_files.py --workers 6 --timeout 420 --json results/test_files.json

critical:
	PYTHONPATH=src pytest -q \
		tests/test_phased_air.py \
		tests/test_phased_permutation.py \
		tests/test_phased_memory.py \
		tests/test_batched_opening.py \
		tests/test_crt_field.py \
		tests/test_canonical_bytes.py \
		tests/test_field_bridge.py \
		tests/test_low_rank_convolution.py \
		tests/test_low_rank_field_bridge.py \
		tests/test_split_limb_field.py \
		tests/test_crt_bridge.py \
		tests/test_bridge_comparison.py \
		tests/test_constraint_backend.py \
		tests/test_projective_vole_lock.py \
		tests/test_real_kzg_we.py \
		tests/test_hybrid_conditional_lock.py \
		tests/test_static_linear_conjunction.py \
		tests/test_batched_inner_product_we.py \
		tests/test_direct_relation_barrier.py \
		tests/test_public_correlation_rank.py \
		tests/test_low_rank_ppe_lock.py \
		tests/test_verifier_shape_frontier.py \
		tests/test_split_basis_ppe_we.py \
		tests/test_basis_separated_kzg.py \
		tests/test_one_sided_wrapper_frontier.py \
		tests/test_hidden_challenge_audit.py \
		tests/test_transcript_mini_lock.py \
		tests/test_shared_proof_binding.py \
		tests/test_ciphertext_free_fault_key.py \
		tests/test_activation_nizk_frontier.py \
		tests/test_fixed_statement_wrapper_candidate.py \
		tests/test_real_dfb_embryo.py

results:
	PYTHONPATH=src python scripts/generate_results.py
	PYTHONPATH=src python scripts/generate_cds_results.py
	PYTHONPATH=src python scripts/generate_v015_results.py
	PYTHONPATH=src python -m ranklock.correlation_seed_experiment
	PYTHONPATH=src python scripts/generate_v017_results.py
	PYTHONPATH=src python scripts/update_v017_status.py
	PYTHONPATH=src python scripts/generate_v018_results.py
	PYTHONPATH=src python scripts/generate_v022_results.py

reproduce:
	./scripts/reproduce.sh

v0241:
	./scripts/reproduce_v0241.sh

v025:
	./scripts/reproduce_v025.sh

release: v025
	PYTHONPATH=src python scripts/build_v025_release.py --output-dir ../release-v0.25

clean:
	rm -rf .pytest_cache src/ranklock/__pycache__ tests/__pycache__ scripts/__pycache__
