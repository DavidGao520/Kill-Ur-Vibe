"""The deterministic API-endpoint classifier: decides which discovered paths are
data/API routes worth an unauthenticated probe, and whether a response body looks
like an exposed DATA collection. Values are NEVER surfaced — only shape/count/keys.
"""

from __future__ import annotations

from kuv.recon.endpoints import (
    classify_json_body,
    is_api_path,
    is_exposed,
    is_search_path,
    resource_name,
)


def test_is_api_path():
    assert is_api_path("/v1/contacts")
    assert is_api_path("/api/users")
    assert is_api_path("/graphql")
    assert is_api_path("/v2/search")
    assert not is_api_path("/account/login")
    assert not is_api_path("/administration")   # 'admin' prefix must not swallow this
    assert not is_api_path("/about")


def test_is_search_path():
    assert is_search_path("/v1/search")
    assert is_search_path("/api/query")
    assert is_search_path("/v1/contacts/find")
    assert not is_search_path("/v1/contacts")


def test_resource_name():
    assert resource_name("/v1/contacts") == "contacts"
    assert resource_name("/api/users") == "users"
    assert resource_name("/v1/search") is None        # a search verb, not a resource
    assert resource_name("/v1/contacts/123") is None   # trailing id, not a resource
    assert resource_name("/about") is None             # not an API path


def test_classify_array_of_records():
    c = classify_json_body(200, "application/json", '[{"id":1,"name":"a"},{"id":2,"name":"b"}]')
    assert c["data_shaped"] and c["shape"] == "array" and c["count"] == 2
    assert "name" in c["keys"] and "id" in c["keys"]


def test_classify_wrapped_list():
    c = classify_json_body(200, "application/json", '{"results":[{"email":"x"}],"total":1}')
    assert c["data_shaped"] and c["shape"] == "object.results[]" and c["count"] == 1
    assert "email" in c["keys"]


def test_classify_elasticsearch_hits():
    c = classify_json_body(
        200, "application/json",
        '{"hits":{"hits":[{"_source":{"name":"a"}}],"total":1}}',
    )
    assert c["data_shaped"] and "hits" in c["shape"]


def test_classify_rejects_non_data():
    assert not classify_json_body(401, "application/json", '{"error":"no"}')["data_shaped"]
    assert not classify_json_body(200, "text/html", "<html>hi</html>")["data_shaped"]
    assert not classify_json_body(200, "application/json", '{"ok":true}')["data_shaped"]
    assert not classify_json_body(200, "application/json", "not json")["data_shaped"]


def test_classifier_never_leaks_values_only_key_names():
    c = classify_json_body(200, "application/json", '[{"ssn":"123-45-6789","name":"Joe Golden"}]')
    blob = str(c)
    assert "123-45-6789" not in blob and "Joe Golden" not in blob
    assert "ssn" in c["keys"] and "name" in c["keys"]


def test_is_exposed_requires_a_data_collection_and_2xx():
    assert is_exposed(200, classify_json_body(200, "application/json", '[{"a":1,"b":2}]'))
    assert not is_exposed(401, classify_json_body(401, "application/json", '[{"a":1}]'))
    assert not is_exposed(200, classify_json_body(200, "application/json", '{"status":"ok"}'))


def test_data_in_key_position_is_not_leaked():
    # A map keyed by emails/UUIDs — the DATA is in the key position. We must drop those
    # keys, never surface them as "field names".
    c = classify_json_body(
        200, "application/json",
        '{"alice@corp.com":1,"bob@corp.com":2,"9f8e-uuid-1":3,"carol@corp.com":4}',
    )
    assert c["data_shaped"] is True                          # still flagged as data
    assert c["keys"] == ()                                   # but no email/uuid escapes
    assert "alice@corp.com" not in str(c) and "9f8e-uuid-1" not in str(c)


def test_large_body_is_flagged_not_silently_dropped():
    # The bigger the leak the more certainly it must be caught, not dropped by a cap.
    big = "[" + ",".join('{"id":%d,"email":"x"}' % i for i in range(200)) + "]"
    c = classify_json_body(200, "application/json", big, parse_cap=100)  # force the oversized path
    assert c["data_shaped"] is True and c["shape"] == "array" and c.get("large") is True
    assert is_exposed(200, c) is True                        # oversized array still 'exposed'


def test_ndjson_bulk_dump_is_data_shaped():
    c = classify_json_body(200, "application/x-ndjson", '{"id":1,"e":"a"}\n{"id":2,"e":"b"}\n{"id":3}')
    assert c["data_shaped"] and c["shape"] == "ndjson" and c["count"] == 3
    assert "id" in c["keys"]


def test_xssi_prefix_is_stripped_before_parse():
    c = classify_json_body(200, "application/json", ")]}',\n[{\"id\":1,\"name\":\"x\"}]")
    assert c["data_shaped"] and c["shape"] == "array"


def test_resource_name_rejects_bare_prefix_segments():
    for junk in ("/v1", "/api", "/graphql", "/rest", "/v2"):
        assert resource_name(junk) is None
    assert resource_name("/v1/contacts") == "contacts"
