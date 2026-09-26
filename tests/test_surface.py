from pathlib import Path
CONTRACT=Path('contracts/contract.py').read_text(encoding='utf-8'); SITE=Path('docs/index.html').read_text(encoding='utf-8')
def test_contract_and_interface_surface():
    for name in ('register_release','scan_release','submit_patch','approve_clearance','expire_quarantine','get_release'):
        assert 'def '+name in CONTRACT and name in SITE
    assert "status:'FINALIZED'" in SITE and '0x38FF51c53b0063513297c355c84Be228E30FfB8f' in SITE
    assert 'advisory_digest' in CONTRACT and 'patch_digests' in CONTRACT
