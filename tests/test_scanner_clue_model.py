from src.scanner import scan_file


def by_type(findings, secret_type):
    return next(f for f in findings if f.secret_type == secret_type)


def test_clue_model_routes_secret_clues_and_detector_signals(tmp_path):
    app = tmp_path / "src" / "app.py"
    app.parent.mkdir(parents=True)

    app.write_text(
        '\n'.join([
            'DATABASE_URL = "postgres://appuser:Str0ngPassw0rdValue987654321@db.internal.local:5432/app"',
            'TWILIO_ACCOUNT_SID = "AC11111111111111111111111111111111"',
            'JWT_VALUE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue123456"',
        ])
    )

    findings = scan_file(app, min_entropy=3.5)

    db = by_type(findings, "Database URL")
    twilio = by_type(findings, "Twilio Account SID")
    jwt = by_type(findings, "JWT Token")

    assert db.classification == "security_clue"
    assert db.clue_type == "database_surface"
    assert db.routes == ["db_surface", "sqli_review", "auth_boundary"]
    assert db.context_clues == ["database_surface"]

    assert twilio.classification == "detector_signal"
    assert twilio.clue_type == "possible_detector_issue"
    assert twilio.routes == ["detector_review"]
    assert twilio.context_clues == []

    assert jwt.classification == "secret_candidate"
    assert jwt.clue_type == "crypto_or_auth_material"
    assert jwt.routes == ["crypto_review", "reuse_check", "fixture_exposure"]
    assert jwt.context_clues == []
