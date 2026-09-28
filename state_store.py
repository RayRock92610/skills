import sqlite3
import os

def init_db(db_path="kessel_flow.db"):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_remediations (
            finding_id TEXT PRIMARY KEY,
            repository TEXT NOT NULL,
            task_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            detector TEXT NOT NULL,          -- 'sentinel'
            remediation_agent TEXT NOT NULL, -- 'jules'
            commit_sha TEXT NOT NULL,
            pr_number INTEGER NOT NULL,
            verification_status TEXT NOT NULL CHECK(verification_status IN ('PENDING', 'CANARY_PASSED', 'FAILED')),
            lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN ('TRIAGED', 'REMEDIATING', 'VALIDATED', 'MERGED', 'OBSERVED')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP
        );
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_remediations_repo_pr ON security_remediations(repository, pr_number);
    """)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
