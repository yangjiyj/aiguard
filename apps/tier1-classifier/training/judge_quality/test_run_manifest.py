import pytest
from metrics import evaluate_run

def test_missing_predictions_cannot_pass():
    inputs=[{"id":"a","label":"attack"},{"id":"b","label":"benign"},{"id":"c","label":"attack"}]
    predictions=[{"id":"a","label":"attack","window_scores":[1.],"coverage_complete":True},
                 {"id":"b","label":"benign","window_scores":[0.],"coverage_complete":True}]
    result=evaluate_run(inputs,predictions,.5)
    assert result["requests"]==3
    assert result["incomplete_attack"]==1
    assert result["missing_ids"]==["c"]
    assert result["passes_point_gate"] is False

def test_extra_duplicate_and_label_drift_rejected():
    inputs=[{"id":"a","label":"attack"}]
    for predictions in [
        [{"id":"z","label":"attack"}],
        [{"id":"a","label":"benign"}],
        [{"id":"a","label":"attack"},{"id":"a","label":"attack"}],
    ]:
        with pytest.raises(ValueError):
            evaluate_run(inputs,predictions,.5)

def test_input_identity_bound_to_report():
    inputs=[{"id":"a","label":"attack"},{"id":"b","label":"benign"}]
    predictions=[{"id":"a","label":"attack","window_scores":[1.],"coverage_complete":True},
                 {"id":"b","label":"benign","window_scores":[0.],"coverage_complete":True}]
    result=evaluate_run(inputs,predictions,.5)
    assert result["passes_point_gate"]
    assert result["missing_ids"]==[]
    assert len(result["expected_rows_sha256"])==64
    changed=[dict(r,packet={"text":"changed"}) for r in inputs]
    assert evaluate_run(changed,predictions,.5)["expected_rows_sha256"]!=result["expected_rows_sha256"]

def test_missing_benign_outputs_are_not_evidence_of_zero_false_positives():
    expected=[{"id":"a","label":"attack"},{"id":"b","label":"benign"}]
    predictions=[{"id":"a","label":"attack","window_scores":[1.],"coverage_complete":True}]
    result=evaluate_run(expected,predictions,.5)
    assert result["fpr_bounds"]==[0.,1.]
    assert result["fpr_ci95"] is None
    assert result["completed_benign_fpr"] is None
    assert result["passes_point_gate"] is False
