"""Actual parser/filesystem/SQLite projection, with stable synthetic subprocess inputs."""

import json
import os
import subprocess
import sys

import pytest
from sqlalchemy import select

from tests.test_native_evidence_context import choice, project
from tests.test_native_evidence_context import (
    fixture as fixture,  # noqa: PLC0414 - pytest fixture export
)
from zacai.intelligence.contracts import (
    IntelligenceResult,
    IntelligenceTask,
    ModelRoute,
    ProcessingStatus,
    ResultStatus,
    RouteIdentity,
    validate_result_for_task,
)
from zacai.intelligence.meeting_review import ReviewContext
from zacai.policy import Destination
from zacai.state import Source

SUBPROCESS = """
import json,sys
from datetime import datetime
from uuid import UUID
from pathlib import Path
from sqlalchemy import create_engine
from tests.test_native_batch_inventory import InventedSqliteSession
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.native_evidence_context import append_native_evidence_context,NativeEvidenceSelection
from zacai.intelligence.contracts import IntelligenceTask,EvidenceReference
from zacai.intelligence.meeting_review import ReviewContext
from zacai.state import Source,SourceClassificationElevation,SourceSystem
from zacai.policy import TrustBoundary as B,DataClassification as C
data=json.loads(sys.stdin.read())
engine=create_engine("sqlite://")
Source.__table__.create(engine)
SourceClassificationElevation.__table__.create(engine)
with InventedSqliteSession(engine,expire_on_commit=False) as sql:
    for row in data["rows"]:
        for k in ("id","supersedes_source_id"):
            if row[k] is not None: row[k]=UUID(row[k])
        row["captured_at"]=datetime.fromisoformat(row["captured_at"])
        row["system"]=SourceSystem(row["system"])
        row["trust_boundary"]=B(row["trust_boundary"])
        row["data_classification"]=C(row["data_classification"])
        sql.add(Source(**row))
    sql.commit()
    result=append_native_evidence_context(
        sql,artifacts=LocalFilesystemArtifactStore(Path(data["store"])),
        context=ReviewContext(IntelligenceTask.model_validate(data["task"]),UUID(data["meeting"])),
        batch_reference=EvidenceReference.model_validate(data["batch"]),
        approval_reference=EvidenceReference.model_validate(data["approval"]),
        approved_proposal_raw=data["proposal"].encode(),
        selections=tuple(NativeEvidenceSelection.model_validate(x) for x in data["selections"]),
        authorized_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({C.CONFIDENTIAL}),
        observed_at=datetime.fromisoformat(data["observed"]),
    )
    print(json.dumps({"event":str(result.context.task.event.event_id),
                      "task":str(result.context.task.task_id)}))
"""


def test_two_capabilities_replay_across_hashseed_processes(fixture):
    sql, args, sources, _, _ = fixture
    task = args["context"].task.model_dump(mode="json")
    task["required_capabilities"] = ["contextual_meeting_review", "structured_extraction"]
    context = ReviewContext(
        IntelligenceTask.model_validate(task), args["context"].meeting_source_id
    )
    selected = choice(sources[-1], "Invented private body")
    # Stable original rows/task/provider artifacts across all subprocesses.
    rows = [dict(row) for row in sql.execute(select(*Source.__table__.columns)).mappings()]
    payload = json.dumps(
        {
            "rows": rows,
            "task": task,
            "meeting": str(context.meeting_source_id),
            "batch": args["batch_reference"].model_dump(mode="json"),
            "approval": args["approval_reference"].model_dump(mode="json"),
            "proposal": args["approved_proposal_raw"].decode(),
            "selections": [selected.model_dump(mode="json")],
            "observed": args["observed_at"].isoformat(),
            "store": str(args["artifacts"].root),
        },
        default=str,
    )
    outputs = []
    for seed in ("0", "1", "2", "3"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        child = subprocess.run(
            [sys.executable, "-c", SUBPROCESS],
            input=payload,
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )
        outputs.append(json.loads(child.stdout))
    assert all(value == outputs[0] for value in outputs)
    assert outputs[0]["task"] != task["task_id"]
    local = project(fixture, (selected,), context=context)
    assert outputs[0]["event"] == str(local.context.task.event.event_id)


def test_original_processed_task_remains_exact_but_new_projection_is_new(fixture):
    _, args, sources, _, _ = fixture
    data = args["context"].task.model_dump()
    data["event"]["processing_status"] = ProcessingStatus.PROCESSED
    task = IntelligenceTask.model_validate(data)
    context = ReviewContext(task, args["context"].meeting_source_id)
    before = task.model_dump_json()
    result = project(fixture, (choice(sources[-1], "Invented private body"),), context=context)
    assert result.original_task.model_dump_json() == before
    assert result.original_event == task.event
    assert task.model_dump_json() == before
    assert result.context.task.task_id != task.task_id
    assert result.context.task.event.processing_status is ProcessingStatus.NEW
    identity = RouteIdentity(provider_id="invented", model_id="invented", runtime_id="offline")
    route = ModelRoute(
        identity=identity,
        destination=Destination.LOCAL,
        capabilities=task.required_capabilities,
        max_input_characters=64000,
        max_output_tokens=task.max_output_tokens,
        estimated_latency_ms=1,
        estimated_cost_usd=0,
        available=True,
    )
    prior = IntelligenceResult(task_id=task.task_id, route=identity, status=ResultStatus.SUCCEEDED)
    assert validate_result_for_task(prior, task, route) == prior
    with pytest.raises(ValueError, match="task/route identity"):
        validate_result_for_task(prior, result.context.task, route)
