import pytest

from app.api.check_input import CheckInputRequest, check_input
from app import ocr


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_check_input_appends_ocr_text_from_image_context(monkeypatch):
    monkeypatch.setattr(ocr, "extract_ocr_text_from_context", lambda context: "身份证号: 12345678901234567X")
    request = CheckInputRequest(
        request_id="req_ocr_001",
        content="请检查这张图片",
        content_type="json",
        context={
            "attachments": [
                {
                    "file_name": "id-card.png",
                    "content_type": "image/png",
                    "data_base64": "aGVsbG8=",
                }
            ]
        },
    )

    response = await check_input(request)
    assert any(f.category == "id_card_cn" for f in response.findings)
