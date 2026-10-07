from app.detector import detect_sensitive_data


def test_email_and_phone_detection():
    result = detect_sensitive_data('Contact John Doe at john.doe@example.com or +1 (555) 123-4567.')
    assert result['summary']['total_entities'] >= 3
    assert 'john.doe@example.com' not in result['redacted_text']
    assert '[EMAIL]' in result['redacted_text']
    assert '[PHONE]' in result['redacted_text']


def test_ssn_and_password_detection():
    result = detect_sensitive_data('My SSN is 123-45-6789 and my password is P@ssw0rd123!')
    assert result['summary']['total_entities'] >= 2
    assert '[SSN]' in result['redacted_text']
    assert '[SECRET]' in result['redacted_text']


def test_no_sensitive_data():
    result = detect_sensitive_data('Project review is scheduled for Tuesday at the office.')
    assert result['summary']['total_entities'] == 0
    assert result['redacted_text'] == 'Project review is scheduled for Tuesday at the office.'
