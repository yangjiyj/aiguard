import pytest
from pretrained_reference import validate_token_windows

def test_missing_tail_is_never_complete():
    assert validate_token_windows([1,2,3,4],[[1,2,3]],1)==(False,3)

def test_overlapping_windows_cover_original_ids_exactly():
    assert validate_token_windows([1,2,3,4,5],[[1,2,3],[3,4,5]],1)==(True,5)

def test_retokens_changed_by_decode_encode_are_rejected():
    with pytest.raises(ValueError):
        validate_token_windows([1,2,3,4],[[1,2,3],[9,4]],1)

def test_extra_duplicate_window_is_rejected():
    with pytest.raises(ValueError):
        validate_token_windows([1,2,3],[[1,2,3],[1,2,3]],1)

def test_loader_rejects_runtime_that_replaces_model_tokenization(tmp_path):
    from tokenizers import Tokenizer,models,normalizers
    from pretrained_reference import verify_tokenizer_behavior
    backend=Tokenizer(models.WordLevel({"[UNK]":0,"Alpha":1,"alpha":2},unk_token="[UNK]"))
    backend.normalizer=normalizers.Lowercase()
    path=tmp_path/"tokenizer.json";backend.save(str(path))
    class WrongRuntime:
        def __call__(self,text,**kwargs):return {"input_ids":[1]}
    with pytest.raises(ValueError,match="tokenizer_artifact_behavior_mismatch"):
        verify_tokenizer_behavior(WrongRuntime(),path,probes=["Alpha"])
