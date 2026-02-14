"""add cloud_findings table

Revision ID: 002
Revises: 001
Create Date: 2026-02-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cloud_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("check_id", sa.String(200), nullable=False, index=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("severity", sa.String(20), nullable=False, index=True),
        sa.Column("severity_score", sa.Float, server_default="5.0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="FAIL", index=True),
        sa.Column("status_detail", sa.Text, server_default=""),
        sa.Column("cloud_provider", sa.String(10), nullable=False, server_default="aws", index=True),
        sa.Column("frameworks", sa.JSON, server_default="[]"),
        sa.Column("requirements", sa.JSON, server_default="[]"),
        sa.Column("resource_type", sa.String(100), server_default=""),
        sa.Column("resource_id", sa.String(500), server_default=""),
        sa.Column("resource_name", sa.String(200), server_default=""),
        sa.Column("resource_region", sa.String(50), server_default=""),
        sa.Column("account_id", sa.String(50), server_default="", index=True),
        sa.Column("remediation", sa.Text, server_default=""),
        sa.Column("remediation_url", sa.String(500), server_default=""),
        sa.Column("scan_source", sa.String(50), server_default="prowler"),
        sa.Column("scan_timestamp", sa.DateTime),
        sa.Column("raw_ocsf", sa.JSON, server_default="{}"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("ix_cloud_findings_check_account", "cloud_findings", ["check_id", "account_id"])
    op.create_index("ix_cloud_findings_severity_status", "cloud_findings", ["severity", "status"])


def downgrade() -> None:
    op.drop_index("ix_cloud_findings_severity_status")
    op.drop_index("ix_cloud_findings_check_account")
    op.drop_table("cloud_findings")
