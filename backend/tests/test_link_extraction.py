from app.core.link_extraction import extract_links, link_identity


def test_no_text_returns_no_links():
    assert extract_links(None) == []
    assert extract_links("") == []
    assert extract_links("تم إيداع راتبكم الشهري بنجاح") == []


def test_scheme_link_inside_arabic_text_drops_arabic_comma():
    text = "عميلنا العزيز، تم إيقاف بطاقتك. ادخل على https://nbe-update.com/login، لتفعيلها."
    assert extract_links(text) == ["https://nbe-update.com/login"]


def test_www_and_bare_domain_links_are_found_in_order():
    text = "Visit www.cib-egypt.net/verify. Or nbe-update.com/login?x=1 now!"
    assert extract_links(text) == ["www.cib-egypt.net/verify", "nbe-update.com/login?x=1"]


def test_bare_egyptian_domains_are_found():
    assert extract_links("ادخل fawry.com أو vodafone.com.eg") == ["fawry.com", "vodafone.com.eg"]


def test_ip_link_with_port_is_found():
    assert extract_links("go to http://192.168.1.5:8080/x now") == ["http://192.168.1.5:8080/x"]


def test_email_addresses_file_names_and_abbreviations_are_not_links():
    text = "email support@cibeg.com or open file.txt, e.g. this. done.Next"
    assert extract_links(text) == []


def test_hostless_scheme_is_dropped_not_raised():
    assert extract_links("a lone https:// here") == []


def test_balanced_brackets_are_kept_and_unbalanced_ones_trimmed():
    text = "(see https://example.com/a_(b)) and (https://example.org/x)"
    assert extract_links(text) == ["https://example.com/a_(b)", "https://example.org/x"]


def test_duplicates_are_removed_keeping_the_first():
    text = "two: https://A.com/ and a.com and HTTPS://a.com"
    assert extract_links(text) == ["https://A.com/"]


def test_unlisted_bare_tld_is_ignored_but_scheme_link_is_not():
    assert extract_links("version.final and readme.md") == []
    assert extract_links("https://report.final/x") == ["https://report.final/x"]


def test_link_identity_ignores_scheme_case_and_trailing_slash():
    assert link_identity("https://X.com/") == link_identity("x.com")
    assert link_identity("https://x.com/a") != link_identity("https://x.com/b")
