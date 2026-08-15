from ranklock.lva_gadget_coverage import (
    InnerProductGadgetApplicability,
    WitnessKind,
    lva_gadget_coverage,
)


def test_66_byte_baseline_applies_only_to_known_scalar_witnesses() -> None:
    gadget = InnerProductGadgetApplicability()
    assert gadget.accepts_witness_kind(WitnessKind.KNOWN_SCALAR)
    assert not gadget.accepts_witness_kind(WitnessKind.BN254_G1_ELEMENT)
    assert gadget.estimated_key_bytes(10) == 790


def test_complete_wrapper_has_no_real_conditional_compiler_yet() -> None:
    report = lva_gadget_coverage()
    summary = report["summary"]
    assert summary["load_bearing_components"] == 6
    assert summary["load_bearing_components_fully_covered"] == 0
    assert summary["load_bearing_components_uncovered"] == 6
    assert summary["complete_conditional_compiler_instantiated"] is False


def test_862kb_number_is_reclassified_as_an_arithmetic_envelope() -> None:
    report = lva_gadget_coverage()
    envelope = report["byte_envelope_classification"]
    assert envelope["activation_plus_future_proof_bytes"] == 862_693
    assert envelope["margin_to_one_MiB_bytes"] == 185_883
    assert envelope["classification"] == "ARITHMETIC_AND_TRANSCRIPT_COORDINATE_ENVELOPE"
    assert envelope["is_actual_serialized_full_LVA_key"] is False
    assert report["breakthrough_target_met"] is False
