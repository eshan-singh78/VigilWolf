"""Property-based tests for data model serialization."""
import pytest
from hypothesis import given, strategies as st
from models import Domain, Group


# Custom strategies for generating valid test data
@st.composite
def valid_dump_mode(draw):
    """Generate valid dump mode values."""
    return draw(st.sampled_from(["html_only", "html_and_assets"]))


@st.composite
def valid_frequency(draw):
    """Generate valid frequency values (positive integers)."""
    return draw(st.integers(min_value=1, max_value=86400))  # 1 second to 1 day


@st.composite
def valid_url(draw):
    """Generate valid HTTP/HTTPS URLs."""
    protocol = draw(st.sampled_from(["http", "https"]))
    domain = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Ll', 'Nd'), min_codepoint=97, max_codepoint=122),
        min_size=3,
        max_size=20
    ))
    tld = draw(st.sampled_from(["com", "org", "net", "io"]))
    return f"{protocol}://{domain}.{tld}"


@st.composite
def valid_group_name(draw):
    """Generate valid group names."""
    return draw(st.text(min_size=1, max_size=100))


# Property 2: Dump mode round-trip consistency
# Feature: domain-monitoring, Property 2: Dump mode round-trip consistency
@given(
    group_id=st.uuids(),
    url=valid_url(),
    dump_mode=valid_dump_mode(),
    frequency=valid_frequency()
)
def test_dump_mode_round_trip_consistency(group_id, url, dump_mode, frequency):
    """
    For any valid dump mode value ("html_only" or "html_and_assets"),
    storing a domain configuration and then retrieving it should return
    the same dump mode.
    
    Validates: Requirements 1.2
    """
    # Create a domain with the given dump mode
    domain = Domain.create(
        group_id=str(group_id),
        url=url,
        dump_mode=dump_mode,
        frequency_seconds=frequency
    )
    
    # Serialize to JSON and deserialize back
    json_str = domain.to_json()
    restored_domain = Domain.from_json(json_str)
    
    # The dump mode should be preserved
    assert restored_domain.dump_mode == dump_mode, \
        f"Dump mode changed from {dump_mode} to {restored_domain.dump_mode}"


# Property 3: Frequency storage consistency
# Feature: domain-monitoring, Property 3: Frequency storage consistency
@given(
    group_id=st.uuids(),
    url=valid_url(),
    dump_mode=valid_dump_mode(),
    frequency=valid_frequency()
)
def test_frequency_storage_consistency(group_id, url, dump_mode, frequency):
    """
    For any positive integer frequency value, storing a domain configuration
    and then retrieving it should return the same frequency value.
    
    Validates: Requirements 1.3
    """
    # Create a domain with the given frequency
    domain = Domain.create(
        group_id=str(group_id),
        url=url,
        dump_mode=dump_mode,
        frequency_seconds=frequency
    )
    
    # Serialize to JSON and deserialize back
    json_str = domain.to_json()
    restored_domain = Domain.from_json(json_str)
    
    # The frequency should be preserved exactly
    assert restored_domain.frequency_seconds == frequency, \
        f"Frequency changed from {frequency} to {restored_domain.frequency_seconds}"


# Additional test to verify both properties together
@given(
    group_id=st.uuids(),
    url=valid_url(),
    dump_mode=valid_dump_mode(),
    frequency=valid_frequency()
)
def test_domain_complete_round_trip(group_id, url, dump_mode, frequency):
    """
    Verify that all domain fields are preserved during serialization round-trip.
    """
    # Create a domain
    domain = Domain.create(
        group_id=str(group_id),
        url=url,
        dump_mode=dump_mode,
        frequency_seconds=frequency
    )
    
    # Serialize to JSON and deserialize back
    json_str = domain.to_json()
    restored_domain = Domain.from_json(json_str)
    
    # All fields should be preserved
    assert restored_domain.id == domain.id
    assert restored_domain.group_id == domain.group_id
    assert restored_domain.url == domain.url
    assert restored_domain.dump_mode == domain.dump_mode
    assert restored_domain.frequency_seconds == domain.frequency_seconds
    assert restored_domain.created_at == domain.created_at
    assert restored_domain.last_checked_at == domain.last_checked_at
    assert restored_domain.active == domain.active


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])
