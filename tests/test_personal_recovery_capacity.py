"""Invented complete inventory. SQLite/owner/age substitutions are not PG proof."""
from uuid import UUID

import pytest

from tests.test_personal_bounded_backup import fixture as fixture  # noqa: PLC0414
from tests.test_personal_fragment_protection import assembled as assembled  # noqa: PLC0414
from tests.test_personal_fragment_protection import call
from zacai import backup_artifacts as backup
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import content_hash_of
from zacai.policy import TrustBoundary
from zacai.state import Source


def populated(f, count):
    row = f['source']
    for n in range(1, count):
        f['session'].add(Source(id=UUID(int=(0xa << 124)+n), trust_boundary=row.trust_boundary,
            data_classification=row.data_classification, system=row.system,
            external_ref=f'invented-{n}', captured_at=row.captured_at,
            content_hash=row.content_hash, content_location=row.content_location))
    f['session'].commit()


def test_complete_source_ceiling_and_preburn_capacity(fixture):
    f=fixture
    populated(f,4091)
    backup._assert_personal_custody_append_capacity(f['session'],5)
    row=f['source']
    f['session'].add(Source(id=UUID(int=(0xa << 124)+4092),trust_boundary=row.trust_boundary,
        data_classification=row.data_classification,system=row.system,
        external_ref='next',captured_at=row.captured_at,content_hash=row.content_hash,
        content_location=row.content_location))
    f['session'].commit()
    with pytest.raises(ValueError,match='before burn'):
        backup._assert_personal_custody_append_capacity(f['session'],5)
    for n in range(4093,4097):
        f['session'].add(Source(id=UUID(int=(0xa << 124)+n),trust_boundary=row.trust_boundary,
            data_classification=row.data_classification,system=row.system,
            external_ref=f'next-{n}',captured_at=row.captured_at,content_hash=row.content_hash,
            content_location=row.content_location))
    f['session'].commit()
    plan=backup.prepare_personal_encrypted_custody_backup_plan(f['session'])
    import json
    assert len(json.loads(plan.rows))==4096
    assert len(plan.artifacts)==1  # no Source omission when ciphertext is deduplicated
    f['session'].add(Source(id=UUID(int=(0xa << 124)+4097),trust_boundary=row.trust_boundary,
        data_classification=row.data_classification,system=row.system,
        external_ref='overflow',captured_at=row.captured_at,content_hash=row.content_hash,
        content_location=row.content_location))
    f['session'].commit()
    with pytest.raises(backup.BackupArtifactsError):
        backup.prepare_personal_encrypted_custody_backup_plan(f['session'])
    assert f['calls']==[]


def test_full_receipt_roundtrip_preserves_every_source_and_fingerprint(assembled):
    base=call(assembled)
    hashes=dict(base.full_boundary_source_hashes)
    fingerprints=dict(base.full_boundary_source_fingerprints)
    for n in range(1,4097):
        if len(hashes)==4096:
            break
        sid=UUID(int=n)
        hashes[sid]=content_hash_of(f'invented-source-{n}'.encode())
        fingerprints[sid]=content_hash_of(f'invented-row-{n}'.encode())
    def values():
        return {**base.model_dump(mode='json'),
            'full_boundary_source_hashes':sorted(hashes.items(),key=lambda x:str(x[0])),
            'full_boundary_source_fingerprints':sorted(fingerprints.items(),key=lambda x:str(x[0]))}
    expanded=protection.PersonalFragmentRecoveryReceipt.model_validate(values())
    raw=protection.encode_personal_fragment_receipt(expanded)
    assert 64000<len(raw)<=2_000_000
    decoded=protection.decode_personal_fragment_receipt(raw)
    assert decoded==expanded and len(decoded.full_boundary_source_hashes)==4096
    assert not decoded.recovery_verified and not decoded.processing_authorized
    fingerprints.pop(next(iter(fingerprints)))
    with pytest.raises(ValueError):
        protection.PersonalFragmentRecoveryReceipt.model_validate(values())
    fingerprints=dict(expanded.full_boundary_source_fingerprints)
    hashes[UUID(int=99999)]='f'*64
    fingerprints[UUID(int=99999)]='e'*64
    with pytest.raises(ValueError):
        protection.PersonalFragmentRecoveryReceipt.model_validate(values())


def test_exact_encrypted_object_set_not_selected_subset(assembled,monkeypatch):
    f=assembled
    from zacai import claude_local_protection as local
    monkeypatch.setattr(f.p,'_access',lambda _:None)
    reads=[]
    def read(reader,key,maximum):
        reads.append(key)
        return key.encode()
    monkeypatch.setattr(local,'_read',read)
    observations=tuple((str(n),content_hash_of(str(n).encode()),100) for n in range(4100))
    f.p._reobserve_objects(observations,object())
    assert reads==[str(n) for n in range(4100)]
    reads.clear()
    corrupted=list(observations);corrupted[-1]=('4099','0'*64,100)
    with pytest.raises(ValueError,match='changed after'):
        f.p._reobserve_objects(tuple(corrupted),object())
    assert len(reads)==4100
    reads.clear()
    with pytest.raises(ValueError,match='bounded exact'):
        f.p._reobserve_objects((*observations,('extra','f'*64,100)),object())
    assert reads==[]


def test_real_manifest_encoder_full_artifact_ceiling():
    manifest=backup.Manifest(TrustBoundary.PERSONAL.value,'2026-10-08T00:00:00+00:00')
    for n in range(4096):
        digest=f'{n:064x}';cipher=f'{n+4096:064x}'
        manifest.entries[digest]=backup.ManifestEntry(digest,f'{digest[:2]}/{digest}.bin',
            f'PERSONAL/{digest[:2]}/{digest}/{cipher}.age',1,cipher,manifest.generated_at)
    raw=manifest.to_json_bytes()
    assert 2_000_000<len(raw)<=4_000_000
    assert backup.Manifest.from_json_bytes(raw).to_json_bytes()==raw
    assert len(backup.Manifest.from_json_bytes(raw).entries)==4096


@pytest.mark.parametrize('family',['AUTHORITY','DECLARATION','ADMISSION','GENERATION','REVIEW_CLAIM','ASSESSMENT'])
def test_all_checkpoint_families_complete_4096_canonical_wire(assembled,family):
    """Declared codec consistency only. These invented refs issue no grant."""
    from datetime import timedelta

    from zacai.intelligence import fragment_publication_admission as admission
    from zacai.intelligence import fragment_publication_generation as generation
    from zacai.intelligence import fragment_publication_review as review
    from zacai.intelligence import fragment_review_retention as declaration
    from zacai.intelligence.contracts import EvidenceReference
    from zacai.policy import DataClassification
    base=call(assembled)
    refs=tuple(EvidenceReference(source_id=UUID(int=8000+n),
        content_hash=content_hash_of(f'invented-reference-{n}'.encode()),
        trust_boundary=TrustBoundary.PERSONAL,
        effective_classification=DataClassification.HIGHLY_RESTRICTED) for n in range(6))
    hashes={r.source_id:r.content_hash for r in refs}
    for n in range(4090):
        hashes[UUID(int=100000+n)]=content_hash_of(f'invented-row-content-{n}'.encode())
    fingerprints={sid:content_hash_of(str(sid).encode()) for sid in hashes}
    ordered=lambda value:tuple(sorted(value.items(),key=lambda x:str(x[0])))
    now=base.verified_at
    values={**base.model_dump(),
        'selected_references':refs,
        'full_boundary_source_hashes':ordered(hashes),
        'full_boundary_source_fingerprints':ordered(fingerprints),
        'publication_reference':refs[0],'publication_digest':'a'*64,
        'admission_reference':refs[1],'admission_digest':refs[1].content_hash,
        'claim_reference':refs[2],'claim_digest':refs[2].content_hash,
        'packet_reference':refs[3],'association_reference':refs[4],
        'subject_reference':refs[2] if family=='REVIEW_CLAIM' else refs[5],
        'subject_digest':refs[2].content_hash if family=='REVIEW_CLAIM' else refs[5].content_hash,
        'reviewer_id':UUID(int=7),'run_id':UUID(int=8),'attempt_id':UUID(int=9),
        'authorization_graph_digest':'b'*64,'review_profile_digest':'c'*64,
        'observed_action_at':now,'consumed_at':now,
        'declared_window_started_at':now,'approved_at':now,
        'expires_at':now+timedelta(minutes=1),
        'original_session_issued_at':base.original_observed_at,
        'original_session_expires_at':now+timedelta(minutes=2),
        'original_session_binding':'d'*64,
        'authority_reference':refs[0],'consent_reference':refs[0],
        'consent_digest':refs[0].content_hash,'kind':'CLAIM' if family=='REVIEW_CLAIM' else 'ASSESSMENT'}
    specs={
        'AUTHORITY':(protection.PersonalFragmentAuthorityReceiptV1,protection.encode_personal_fragment_authority_receipt,protection.decode_personal_fragment_authority_receipt),
        'DECLARATION':(declaration.PersonalFragmentDeclarationReceiptV2,declaration.encode_fragment_declaration_receipt,declaration.decode_fragment_declaration_receipt),
        'ADMISSION':(admission.PersonalFragmentPublicationAdmissionReceiptV1,admission.encode_fragment_publication_admission_receipt,admission.decode_fragment_publication_admission_receipt),
        'GENERATION':(generation.PersonalFragmentPublicationClaimReceiptV1,generation.encode_publication_claim_receipt,generation.decode_publication_claim_receipt),
        'REVIEW_CLAIM':(review.PersonalFragmentPublicationReviewReceiptV1,review.encode_publication_review_receipt,review.decode_publication_review_receipt),
        'ASSESSMENT':(review.PersonalFragmentPublicationReviewReceiptV1,review.encode_publication_review_receipt,review.decode_publication_review_receipt)}
    if family=='AUTHORITY':
        values.update(kind='CONSENT',attempt_id=None,consumed_at=None)
    cls,encode,decode=specs[family]
    declared={k:v for k,v in values.items() if k in cls.model_fields and k!='format'}
    receipt=cls.model_validate(declared)
    raw=encode(receipt)
    assert 64000<len(raw)<=2_000_000
    assert decode(raw)==receipt
    assert not receipt.recovery_verified and not receipt.processing_authorized
    changed=dict(declared)
    changed['full_boundary_source_fingerprints']=declared['full_boundary_source_fingerprints'][:-1]
    with pytest.raises(ValueError):
        cls.model_validate(changed)
    changed=dict(declared)
    changed['full_boundary_source_hashes']=(*declared['full_boundary_source_hashes'],(UUID(int=999999),'f'*64))
    changed['full_boundary_source_fingerprints']=(*declared['full_boundary_source_fingerprints'],(UUID(int=999999),'e'*64))
    with pytest.raises(ValueError):
        cls.model_validate(changed)


def test_oversized_receipt_ciphertext_holds_before_receipt_put(assembled,monkeypatch):
    from zacai import claude_local_protection as local
    f=assembled
    original=local._crypt
    reached=[]
    def encrypt(raw,recipient,maximum):
        if maximum==2_000_000:
            reached.append("receipt-encrypted")
            return b"x"*2_100_001
        return original(raw,recipient,maximum)
    monkeypatch.setattr(local,"_crypt",encrypt)
    writes=[]
    actual=f.writer.put_object
    def put(key,raw):
        writes.append(key)
        return actual(key,raw)
    monkeypatch.setattr(f.writer,"put_object",put)
    with pytest.raises(protection.ContextualProtectionError):
        call(f)
    assert reached==["receipt-encrypted"]
    assert not any("/receipt-" in key for key in writes)
