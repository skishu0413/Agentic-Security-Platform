import json
from pathlib import Path

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
    assert any(f["cwe"] == "CWE-94" for f in result["findings"])


def test_benchmark_performance_exceeds_targets():
    report = benchmark_performance()

    assert report["simple_problem_gain_pct"] > 35
    assert report["large_backend_gain_pct"] > 20


def test_platform_reports_provider_statuses():
    platform = AgenticSecurityPlatform()
    status = platform.provider_status()

    assert set(status.keys()) == {"openai", "claude", "ollama"}
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
    assert data["summary"]["provider_count"] == 3
