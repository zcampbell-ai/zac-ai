"""Append-only reviewed meeting project context (D034C).

Revision ID: 0005
Revises: 0004
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _boundary(name: str) -> sa.Enum:
    return sa.Enum(
        "PERSONAL", "BRAINSTORM", "SHARED", name=name, native_enum=False, create_constraint=True
    )


def upgrade() -> None:
    op.create_table(
        "meeting_project_association",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("meeting_id", sa.UUID(), nullable=False),
        sa.Column("project_id", sa.UUID(), nullable=False),
        sa.Column("reviewed_project_version", sa.Integer(), nullable=False),
        sa.Column(
            "trust_boundary",
            _boundary("meeting_project_association_trust_boundary"),
            nullable=False,
        ),
        sa.Column(
            "data_classification",
            sa.Enum(
                "PUBLIC",
                "INTERNAL",
                "CONFIDENTIAL",
                "HIGHLY_RESTRICTED",
                name="meeting_project_association_data_classification",
                native_enum=False,
                create_constraint=True,
            ),
            nullable=False,
        ),
        sa.Column("confirmation_source_id", sa.UUID(), nullable=False),
        sa.Column(
            "noted_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "trust_boundary", name="uq_meeting_project_association_boundary"),
        sa.ForeignKeyConstraint(
            ["meeting_id", "trust_boundary"], ["meeting.id", "meeting.trust_boundary"]
        ),
        sa.ForeignKeyConstraint(
            ["project_id", "reviewed_project_version", "trust_boundary"],
            ["project.entity_id", "project.version", "project.trust_boundary"],
        ),
        sa.ForeignKeyConstraint(
            ["confirmation_source_id", "trust_boundary"], ["source.id", "source.trust_boundary"]
        ),
    )
    op.create_table(
        "meeting_project_association_retraction",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("association_id", sa.UUID(), nullable=False),
        sa.Column(
            "trust_boundary",
            _boundary("meeting_project_association_retraction_trust_boundary"),
            nullable=False,
        ),
        sa.Column("confirmation_source_id", sa.UUID(), nullable=False),
        sa.Column(
            "retracted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("association_id", name="uq_meeting_project_association_retraction"),
        sa.ForeignKeyConstraint(
            ["association_id", "trust_boundary"],
            ["meeting_project_association.id", "meeting_project_association.trust_boundary"],
        ),
        sa.ForeignKeyConstraint(
            ["confirmation_source_id", "trust_boundary"], ["source.id", "source.trust_boundary"]
        ),
    )
    for table in ("meeting_project_association", "meeting_project_association_retraction"):
        op.execute(
            f"CREATE TRIGGER {table}_forbid_mutation BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION zacai_forbid_mutation();"
        )


def downgrade() -> None:
    op.drop_table("meeting_project_association_retraction")
    op.drop_table("meeting_project_association")
