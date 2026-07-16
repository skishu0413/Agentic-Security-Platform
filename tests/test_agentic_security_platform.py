import json
from pathlib import Path
from unittest.mock import MagicMock

from agentic_security_platform import (
    AgenticSecurityPlatform,
    benchmark_performance,
    evaluate_source_code,
)


def test_evaluate_source_code_detects_insecure_patterns(tmp_path):
    sample = tmp_path / "unsafe.py"
    sample.write_text(
        "import os\n"
        "import subprocess\n"
        "cmd = 'echo hi'\n"
        "subprocess.run(cmd, shell=True)\n"
        "eval('2+2')\n",
        encoding="utf-8",
    )

    result = evaluate_source_code(sample.read_text(encoding="utf-8"), str(sample))

    assert result["summary"]["finding_count"] >= 2
    assert any(f["cwe"] == "CWE-78" for f in result["findings"])


def test_benchmark_performance_exceeds_targets():
    report = benchmark_performance()

    assert report["simple_problem_gain_pct"] > 35
    assert report["large_backend_gain_pct"] > 20


def test_platform_reports_provider_statuses():
    platform = AgenticSecurityPlatform()
    status = platform.provider_status()

    assert set(status.keys()) == {"openai", "claude", "ollama", "cursor"}
    assert all(isinstance(v["enabled"], bool) for v in status.values())


def test_platform_export_json(tmp_path):
    platform = AgenticSecurityPlatform()
    source_path = tmp_path / "sample.py"
    source_path.write_text("print('hello')\n", encoding="utf-8")

    result = platform.run_review(str(source_path))
    output_path = tmp_path / "report.json"
    platform.export_report(result, output_path)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["summary"]["finding_count"] >= 0
    assert data["summary"]["provider_count"] == 4


def test_parse_llm_json():
    platform = AgenticSecurityPlatform()
    
    clean_list = '[{"rule": "test-rule", "cwe": "CWE-123", "severity": "high", "description": "Test"}]'
    res = platform._parse_llm_json(clean_list)
    assert len(res) == 1
    assert res[0]["rule"] == "test-rule"
    
    md_wrapped = '```json\n{"findings": [{"rule": "test-rule-2", "cwe": "CWE-456", "severity": "low", "description": "Test 2"}]}\n```'
    res = platform._parse_llm_json(md_wrapped)
    assert len(res) == 1
    assert res[0]["rule"] == "test-rule-2"


def test_ai_scanning_mocked(monkeypatch):
    platform = AgenticSecurityPlatform()
    monkeypatch.setattr("agentic_security_platform.check_provider_configured", lambda p: p == "openai")
    
    mock_client = MagicMock()
    mock_message = MagicMock()
    mock_message.content = '{"findings": [{"rule": "ai-injection", "cwe": "CWE-78", "severity": "high", "description": "AI"}]}'
    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_client.chat.completions.create.return_value = MagicMock(choices=[mock_choice])
    
    monkeypatch.setattr("openai.OpenAI", lambda **kwargs: mock_client)
    monkeypatch.setenv("OPENAI_API_KEY", "mock-key")
    
    result = evaluate_source_code("some benign code", "dummy.py", enabled_providers=["openai"], platform_instance=platform)
    assert result["summary"]["finding_count"] == 1
    assert result["findings"][0]["rule"] == "ai-injection"
    assert result["findings"][0]["cwe"] == "CWE-78"
    assert result["findings"][0]["severity"] == "high"


def test_cwe_helper_and_enrichment():
    from cwe_helper import get_cwe_details, map_bandit_cwe
    
    # Test offline local DB lookup
    details = get_cwe_details("CWE-78")
    assert "OS Command Injection" in details["title"]
    assert "OS command" in details["description"]
    
    # Test Bandit mapping
    assert map_bandit_cwe("B608", {"id": 89}) == "CWE-89"
    assert map_bandit_cwe("unknown_id", {"id": 123}) == "CWE-123"

