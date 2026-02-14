"""Initial VulnPilot AI schema - all tables

Revision ID: 001_initial
Revises: None
Create Date: 2025-02-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Vulnerabilities ---
    op.create_table('vulnerabilities',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('cve_id', sa.String(20), nullable=False, index=True),
        sa.Column('source_scanner', sa.String(50), nullable=False),
        sa.Column('source_id', sa.String(100)),
        sa.Column('cvss_base_score', sa.Float(), default=0.0),
        sa.Column('cvss_vector', sa.String(200)),
        sa.Column('cvss_version', sa.String(10)),
        sa.Column('title', sa.String(500)),
        sa.Column('description', sa.Text()),
        sa.Column('solution', sa.Text()),
        sa.Column('cwe_id', sa.String(20)),
        sa.Column('published_date', sa.DateTime()),
        sa.Column('last_modified', sa.DateTime()),
        sa.Column('hostname', sa.String(255), index=True),
        sa.Column('ip_address', sa.String(45), index=True),
        sa.Column('port', sa.Integer()),
        sa.Column('protocol', sa.String(10)),
        sa.Column('os', sa.String(200)),
        sa.Column('software', sa.String(500)),
        sa.Column('asset_tier', sa.String(10), default='tier_3'),
        sa.Column('business_unit', sa.String(100)),
        sa.Column('owner', sa.String(100)),
        sa.Column('is_internet_facing', sa.Boolean(), default=False),
        sa.Column('has_waf', sa.Boolean(), default=False),
        sa.Column('has_ips', sa.Boolean(), default=False),
        sa.Column('is_segmented', sa.Boolean(), default=False),
        sa.Column('raw_data', sa.JSON()),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_vuln_cve_ip', 'vulnerabilities', ['cve_id', 'ip_address'])

    # --- Assets ---
    op.create_table('assets',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('hostname', sa.String(255), unique=True, index=True),
        sa.Column('ip_address', sa.String(45), index=True),
        sa.Column('asset_tier', sa.String(10), default='tier_3'),
        sa.Column('business_unit', sa.String(100)),
        sa.Column('environment', sa.String(50)),
        sa.Column('owner', sa.String(100)),
        sa.Column('owner_email', sa.String(200)),
        sa.Column('escalation_contact', sa.String(100)),
        sa.Column('escalation_email', sa.String(200)),
        sa.Column('is_internet_facing', sa.Boolean(), default=False),
        sa.Column('network_zone', sa.String(50), default='internal'),
        sa.Column('has_waf', sa.Boolean(), default=False),
        sa.Column('has_ips', sa.Boolean(), default=False),
        sa.Column('is_segmented', sa.Boolean(), default=False),
        sa.Column('has_edr', sa.Boolean(), default=False),
        sa.Column('os', sa.String(200)),
        sa.Column('compensating_controls', sa.JSON()),
        sa.Column('tags', sa.JSON()),
        sa.Column('cmdb_id', sa.String(100)),
        sa.Column('last_scan_date', sa.DateTime()),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # --- VPRS Scores ---
    op.create_table('vprs_scores',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('vulnerability_id', sa.Integer(), sa.ForeignKey('vulnerabilities.id'), nullable=False),
        sa.Column('vprs_score', sa.Float(), nullable=False),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('epss_score_used', sa.Float()),
        sa.Column('epss_component', sa.Float()),
        sa.Column('kev_match', sa.Boolean(), default=False),
        sa.Column('kev_component', sa.Float()),
        sa.Column('dark_web_score', sa.Float()),
        sa.Column('dark_web_component', sa.Float()),
        sa.Column('asset_score', sa.Float()),
        sa.Column('asset_component', sa.Float()),
        sa.Column('reachability_score', sa.Float()),
        sa.Column('reachability_component', sa.Float()),
        sa.Column('controls_score', sa.Float()),
        sa.Column('controls_component', sa.Float()),
        sa.Column('weights_used', sa.JSON()),
        sa.Column('hard_rule_triggered', sa.Boolean(), default=False),
        sa.Column('hard_rule_name', sa.String(100)),
        sa.Column('justifier_score', sa.Float()),
        sa.Column('challenger_score', sa.Float()),
        sa.Column('debate_reasoning', sa.Text()),
        sa.Column('debate_consensus', sa.Boolean()),
        sa.Column('justification', sa.Text()),
        sa.Column('llm_provider', sa.String(50)),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )
    op.create_index('ix_vprs_vuln_id', 'vprs_scores', ['vulnerability_id'])
    op.create_index('ix_vprs_severity', 'vprs_scores', ['severity'])

    # --- Tickets ---
    op.create_table('tickets',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('cve_id', sa.String(20), nullable=False, index=True),
        sa.Column('external_id', sa.String(100)),
        sa.Column('external_url', sa.String(500)),
        sa.Column('provider', sa.String(50)),
        sa.Column('title', sa.String(500)),
        sa.Column('description', sa.Text()),
        sa.Column('priority', sa.String(10)),
        sa.Column('status', sa.String(20), default='open'),
        sa.Column('assigned_to', sa.String(100)),
        sa.Column('vprs_score', sa.Float()),
        sa.Column('severity', sa.String(20)),
        sa.Column('sla_hours', sa.Integer()),
        sa.Column('sla_deadline', sa.DateTime()),
        sa.Column('sla_status', sa.String(20), default='on_track'),
        sa.Column('escalation_count', sa.Integer(), default=0),
        sa.Column('resolved_at', sa.DateTime()),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now()),
    )

    # --- Audit Log ---
    op.create_table('audit_log',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('cve_id', sa.String(20)),
        sa.Column('details', sa.JSON()),
        sa.Column('user', sa.String(100)),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now()),
    )

    # --- Drift Events ---
    op.create_table('drift_events',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('cve_id', sa.String(20), nullable=False, index=True),
        sa.Column('previous_score', sa.Float()),
        sa.Column('new_score', sa.Float()),
        sa.Column('previous_severity', sa.String(20)),
        sa.Column('new_severity', sa.String(20)),
        sa.Column('drift_reason', sa.Text()),
        sa.Column('detected_at', sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table('drift_events')
    op.drop_table('audit_log')
    op.drop_table('tickets')
    op.drop_table('vprs_scores')
    op.drop_table('assets')
    op.drop_table('vulnerabilities')
