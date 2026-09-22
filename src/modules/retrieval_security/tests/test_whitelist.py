"""白名单专项测试。"""

from checks.whitelist_check import is_whitelisted


def test_whitelist_hit_domain():
    hit, reason = is_whitelisted("https://internal.company.com/doc")
    assert hit is True


def test_whitelist_hit_prefix():
    hit, reason = is_whitelisted("https://trusted.wiki.org/page")
    assert hit is True


def test_whitelist_hit_exact():
    hit, reason = is_whitelisted("https://approved.example.com/doc-001")
    assert hit is True


def test_whitelist_miss():
    hit, reason = is_whitelisted("https://evil.com/doc")
    assert hit is False


def test_whitelist_unknown():
    hit, reason = is_whitelisted("unknown")
    assert hit is False


def test_whitelist_empty():
    hit, reason = is_whitelisted("")
    assert hit is False


def test_whitelist_bypass():
    # 域名边界校验：internal.company.com 不应匹配 internal.company.com.evil.com
    hit, reason = is_whitelisted("https://internal.company.com.evil.com/doc")
    assert hit is False
