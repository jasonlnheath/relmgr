"""Tests for normalizer module."""

import pytest
from normalizer import (
    normalize_name,
    normalize_phone,
    normalize_email,
    normalize_contact,
)


class TestNormalizeName:
    def test_last_first(self):
        normalized, first, last = normalize_name("Smith, John")
        assert normalized == "Smith, John"
        assert first == "John"
        assert last == "Smith"

    def test_first_last(self):
        normalized, first, last = normalize_name("John Smith")
        assert normalized == "Smith, John"
        assert first == "John"
        assert last == "Smith"

    def test_middle_initial(self):
        normalized, first, last = normalize_name("John M. Smith")
        assert normalized == "Smith, John"
        assert first == "John"
        assert last == "Smith"

    def test_with_title(self):
        normalized, first, last = normalize_name("Dr. John Smith")
        assert first == "John"
        assert last == "Smith"

    def test_empty(self):
        normalized, first, last = normalize_name("")
        assert normalized == ""
        assert first == ""
        assert last == ""

    def test_single_name(self):
        normalized, first, last = normalize_name("Madonna")
        assert normalized == "Madonna"
        assert first == "Madonna"
        assert last == ""


class TestNormalizePhone:
    def test_us_number(self):
        result = normalize_phone("(555) 123-4567")
        assert result == "+15551234567"

    def test_e164(self):
        result = normalize_phone("+15551234567")
        assert result == "+15551234567"

    def test_empty(self):
        result = normalize_phone("")
        assert result is None

    def test_invalid(self):
        result = normalize_phone("abc")
        assert result is None


class TestNormalizeEmail:
    def test_basic(self):
        result = normalize_email("john@example.com")
        assert result["address"] == "john@example.com"
        assert result["type"] == "work"

    def test_personal_domain(self):
        result = normalize_email("john@gmail.com")
        assert result["type"] == "personal"

    def test_dict_input(self):
        result = normalize_email({"value": "john@test.com", "type": "home"})
        assert result["address"] == "john@test.com"
        assert result["type"] == "home"

    def test_empty(self):
        result = normalize_email("")
        assert result is None


class TestNormalizeContact:
    def test_google_format(self):
        raw = {
            "id": "google_123",
            "name": "John Smith",
            "emails": [{"value": "john@example.com"}],
            "phones": [{"value": "+15551234567"}],
            "organizations": [{"name": "Acme Corp", "title": "Engineer"}],
        }
        result = normalize_contact(raw, "google")
        assert result["normalized_name"] == "Smith, John"
        assert result["first_name"] == "John"
        assert result["last_name"] == "Smith"
        assert len(result["emails"]) == 1
        assert len(result["organizations"]) == 1

    def test_vcf_format(self):
        raw = {
            "id": "vcf_456",
            "name": "Doe, Jane",
            "emails": [{"value": "jane@example.com"}],
            "phones": [],
            "organizations": [],
        }
        result = normalize_contact(raw, "apple")
        assert result["normalized_name"] == "Doe, Jane"
        assert result["first_name"] == "Jane"
        assert result["last_name"] == "Doe"
