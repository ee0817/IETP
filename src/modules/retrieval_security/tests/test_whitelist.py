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


# ---------------------------------------------------------------------------
# PR4 修复验证：端口与 userinfo 处理（P1-7）
# ---------------------------------------------------------------------------

def test_whitelist_domain_with_port():
    """带端口的可信域名应命中（hostname 剥离端口）。"""
    hit, _ = is_whitelisted("https://internal.company.com:8443/doc")
    assert hit is True


def test_whitelist_userinfo_bypass():
    """userinfo 绕过：https://internal.company.com@evil.com/ 不得命中。"""
    hit, _ = is_whitelisted("https://internal.company.com@evil.com/doc")
    assert hit is False


def test_url_prefix_boundary(tmp_path, monkeypatch):
    """N3：url_prefix 无尾斜杠时不得误配相似域名。"""
    import checks.whitelist_check as wc

    fake_config = tmp_path / "whitelist.yaml"
    fake_config.write_text(
        'version: 1\nrules:\n  - type: url_prefix\n    value: "https://trusted.wiki.org"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(wc, "_CONFIG_PATH", fake_config)
    wc.reload_rules()

    # 无尾斜杠规则：正常子路径命中
    assert bool(is_whitelisted("https://trusted.wiki.org/page")) is True
    # 但相似域名不得命中
    assert bool(is_whitelisted("https://trusted.wiki.org.evil.com/x")) is False

    # 恢复真实配置缓存，避免污染后续测试
    monkeypatch.undo()
    wc.reload_rules()


def test_exact_match_case_sensitive_path(tmp_path, monkeypatch):
    """N4：exact 匹配仅 host/scheme 归一化，path 大小写敏感。"""
    import checks.whitelist_check as wc

    fake_config = tmp_path / "whitelist.yaml"
    fake_config.write_text(
        'version: 1\nrules:\n  - type: exact\n    value: "https://approved.example.com/doc-001"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(wc, "_CONFIG_PATH", fake_config)
    wc.reload_rules()

    # host 大小写不同 → 命中（host 不区分大小写）
    assert bool(is_whitelisted("HTTPS://APPROVED.EXAMPLE.COM/doc-001")) is True
    # path 大小写不同 → 不得命中
    assert bool(is_whitelisted("https://approved.example.com/DOC-001")) is False

    monkeypatch.undo()
    wc.reload_rules()
