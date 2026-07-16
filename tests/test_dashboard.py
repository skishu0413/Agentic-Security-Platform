from fastapi.testclient import TestClient

from app import app


def test_dashboard_endpoint():
    client = TestClient(app)
    response = client.get('/api/dashboard/stats')
    assert response.status_code == 200
    data = response.json()
    assert 'summary' in data
    assert 'findings' in data
    assert 'providers' in data


def test_dashboard_scan_endpoint(tmp_path):
    client = TestClient(app)
    sample = tmp_path / "test.py"
    sample.write_text("import subprocess\nsubprocess.run('cmd', shell=True)\n", encoding="utf-8")

    response = client.post('/api/dashboard/scan', json={'source_path': str(sample)})
    assert response.status_code == 200
    data = response.json()
    assert data['status'] == 'ok'
    assert 'findings_count' in data


def test_dashboard_export_endpoint():
    client = TestClient(app)
    response = client.get('/api/dashboard/export')
    assert response.status_code == 200
    assert response.headers['content-disposition'] == 'attachment; filename=security_report.json'
    data = response.json()
    assert 'summary' in data
    assert 'findings' in data
    assert 'providers' in data
