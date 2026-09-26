from conftest import CONTRACT
import hashlib, json

POLICY='https://policy.example/release'; MANIFEST='https://manifest.example/lock'; ADVISORY='https://advisory.example/CVE-77'

def base(vm,deploy,alice,bob):
    vm.strict_mocks=True; vm.check_pickling=True; vm.warp('2034-01-01T00:00:00+00:00'); vm.sender=alice
    vm.mock_web(r'policy\.example',{'status':200,'body':'Policy: quarantine HIGH or CRITICAL affected dependencies.'})
    vm.mock_web(r'manifest\.example',{'status':200,'body':'app 4.0 locks quartz-lib 1.2.0'})
    contract=deploy(CONTRACT); contract.register_release('rel-77','0x'+bob.hex(),'app','4.0',POLICY,MANIFEST,ADVISORY,3600); return contract

def affected(vm):
    vm.mock_web(r'advisory\.example',{'status':200,'body':'CVE-77 affects quartz-lib versions below 1.3.0. Severity HIGH.'})
    vm.mock_llm(r'.*PatchSemaphore security scan.*','{"affected":true,"severity":"HIGH","component":"quartz-lib"}')

def patch(vm,resolved=True):
    vm.mock_web(r'patched\.example',{'status':200,'body':'app 4.0.1 locks quartz-lib 1.3.2'})
    vm.mock_web(r'audit\.example',{'status':200,'body':'Remediation report confirms quartz-lib 1.3.2 deployed.'})
    vm.mock_llm(r'.*PatchSemaphore remediation review.*',json.dumps({'resolved':resolved,'patched_version':'1.3.2' if resolved else '1.2.0'}))

def test_quarantine_patch_and_reviewer_clearance(direct_vm,direct_deploy,direct_alice,direct_bob):
    c=base(direct_vm,direct_deploy,direct_alice,direct_bob); affected(direct_vm); c.scan_release('rel-77'); assert c.get_release('REL-77')['state']=='QUARANTINED'
    direct_vm.clear_mocks(); patch(direct_vm); c.submit_patch('rel-77','https://patched.example/lock','https://audit.example/report'); assert c.get_release('rel-77')['state']=='AWAITING_REVIEW'
    direct_vm.sender=direct_bob; c.approve_clearance('rel-77'); assert c.get_release('rel-77')['state']=='CLEARED'

def test_forged_scan_output_is_rejected(direct_vm,direct_deploy,direct_alice,direct_bob):
    c=base(direct_vm,direct_deploy,direct_alice,direct_bob); affected(direct_vm); result=c._scan(c.releases['REL-77']); assert direct_vm.run_validator(leader_result=result) is True
    forged=dict(result); forged['advisory_digest']=hashlib.sha256(b'forged').hexdigest(); assert direct_vm.run_validator(leader_result=forged) is False

def test_insufficient_patch_can_be_retried(direct_vm,direct_deploy,direct_alice,direct_bob):
    c=base(direct_vm,direct_deploy,direct_alice,direct_bob); affected(direct_vm); c.scan_release('rel-77'); direct_vm.clear_mocks(); patch(direct_vm,False); c.submit_patch('rel-77','https://patched.example/lock','https://audit.example/report'); assert c.get_release('rel-77')['state']=='QUARANTINED' and c.get_release('rel-77')['patch_attempts']==1
    direct_vm.clear_mocks(); patch(direct_vm,True); c.submit_patch('rel-77','https://patched.example/lock','https://audit.example/report'); assert c.get_release('rel-77')['state']=='AWAITING_REVIEW' and c.get_release('rel-77')['patch_attempts']==2

def test_role_and_permissionless_expiry(direct_vm,direct_deploy,direct_alice,direct_bob,direct_charlie):
    c=base(direct_vm,direct_deploy,direct_alice,direct_bob); affected(direct_vm); c.scan_release('rel-77'); direct_vm.clear_mocks(); patch(direct_vm); direct_vm.sender=direct_charlie
    with direct_vm.expect_revert('timely maintainer patch'): c.submit_patch('rel-77','https://patched.example/lock','https://audit.example/report')
    direct_vm.warp('2034-01-01T01:00:01+00:00'); c.expire_quarantine('rel-77'); assert c.get_release('rel-77')['state']=='EXPIRED'

def test_duplicate_origins_are_rejected(direct_vm,direct_deploy,direct_alice,direct_bob):
    direct_vm.sender=direct_alice; c=direct_deploy(CONTRACT)
    with direct_vm.expect_revert('complete independent release registration required'):
        c.register_release('dup','0x'+direct_bob.hex(),'app','1','https://same.example/policy','https://same.example/manifest',ADVISORY,600)
