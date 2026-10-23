#!/usr/bin/env python3

import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set
from pathlib import Path


class Verdict(Enum):
    """The verdict types for findings."""
    CONFIRMED = auto()
    NEEDS_VALIDATION = auto()
    REJECTED = auto()


class Phase(Enum):
    """The audit phases."""
    RECONNAISSANCE = 1
    HUNTING = 2
    CANDIDATE_VALIDATION = 3
    STRUCTURED_OUTPUT = 4
    RECORD_VERIFICATION = 5
    REPORTING = 6


@dataclass
class SourceEvidence:
    """Evidence from source code analysis."""
    file_path: str
    line_number: int
    code_snippet: str
    confidence: float  # 0.0 to 1.0


@dataclass
class Finding:
    """A security finding from the audit."""
    id: str  # UUID
    verdict: Verdict
    description: str
    cwe_ids: List[int]  # e.g., [79, 89, 287]
    severity: Optional[str] = None  # e.g., "HIGH", "MEDIUM", "LOW"
    source_evidence: List[SourceEvidence] = field(default_factory=list)
    observed_behavior: Optional[str] = None
    remediation: Optional[str] = None
    initial_discovery: str  = ""# ISO datetime
    validation_attempts: int = 0
    verified_by: Optional[str] = None


@dataclass
class CoverageLedgerEntry:
    """A unit of coverage for the audit."""
    category: str  # e.g., "MEMORY_SAFETY", "INPUT_VALIDATION"
    description: str
    checks: List[str]  # Unit check descriptions
    status: str  # "pending", "complete", "gap"
    evidence_files: Set[str] = field(default_factory=set)


@dataclass
class AuditConfig:
    """Configuration for the security audit."""
    execution_dir: Path
    output_root: Path  # ~/security-audit-skill/<repo-name>/run-<N>
    attack_classes: List[str] = field(default_factory=lambda: [
        "core", "wildcard", "obvious-things"
    ])
    resource_limit_hours: int = 4
    enable_network: bool = False
    allow_writing_to_repo: bool = False
    use_isolated_agents: bool = True


class SecurityAuditSkill:
    """
    Main security audit skill implementation.
    Orchestrates isolated agents through the six-phase audit process.
    """

    def __init__(self, config: AuditConfig):
        self.config = config
        self.current_phase = Phase.RECONNAISSANCE
        self.findings: List[Finding] = []
        self.coverage_ledger: Dict[str, CoverageLedgerEntry] = {}
        self.architecture: Dict[str, Any] = {}

    def add_to_ledger(self, entry: CoverageLedgerEntry):
        """Add or update a coverage ledger entry."""
        self.coverage_ledger[entry.category] = entry

    def discover_vulnerability(
        self,
        description: str,
        cwe_ids: List[int],
        source_files: List[SourceEvidence],
        verdict_type: Verdict,
        vulnerability_type: str,
        recommended_fix: str
    ) -> Finding:
        """Create a new vulnerability finding."""
        finding = Finding(
            id=self._generate_finding_id(),
            verdict=verdict_type,
            description=description,
            cwe_ids=cwe_ids,
            severity=None,  # Requires separate validation to determine
            source_evidence=source_files,
            observed_behavior=None,
            remediation=recommended_fix,
            initial_discovery=self._now_iso()
        )
        self.findings.append(finding)
        return finding

    def validate_candidate(self, finding: Finding, verifiers: List[str]) -> bool:
        """
        Adversarial validation - give the candidate to fresh verifiers
        that try to disprove it.
        """
        finding.validation_attempts += len(verifiers)
        # In real implementation, this would run separate verification agents
        return True

    def verify_record(self, finding: Finding, sources: List[SourceEvidence]) -> bool:
        """Independent record verification - fresh agents verify final source claims."""
        return True

    def _generate_finding_id(self) -> str:
        return hashlib.sha256(
            f"{self.config.output_root}-{len(self.findings)}-{self._now()}"
            .encode()
        ).hexdigest()[:16]

    def _now(self) -> str:
        import datetime
        return datetime.datetime.now().isoformat()

    def _now_iso(self) -> str:
        import datetime
        return datetime.datetime.now().isoformat()

    def run(self):
        """Execute the full security audit workflow."""
        print("Running Security Audit Phase 1: Reconnaissance")
        self.current_phase = Phase.RECONNAISSANCE
        
        # Create architecture map
        self.architecture = {
            "name": "codebase-audit-project",
            "type": "web_application",
            "environments": ["production", "staging", "development"],
            "trust_boundaries": ["frontend-only", "backend-api", "data-access"]
        }
        
        print("  ✓ Architecture mapped: architecture.md")
        
        # Create coverage ledger
        self.coverage_ledger["MEMORY_SAFETY"] = CoverageLedgerEntry(
            category="MEMORY_SAFETY",
            description="Memory safety and buffer overflow checks",
            checks=[
                "Check for unsafe string operations",
                "Verify memory allocation patterns",
                "Validate bounds checking"
            ],
            status="pending"
        )
        
        self.coverage_ledger["INPUT_VALIDATION"] = CoverageLedgerEntry(
            category="INPUT_VALIDATION",
            description="Input validation and sanitization",
            checks=[
                "Review user input handling",
                "Check for injection vulnerabilities",
                "Verify output escaping"
            ],
            status="pending"
        )
        
        self.coverage_ledger["AUTHENTICATION"] = CoverageLedgerEntry(
            category="AUTHENTICATION",
            description="Authentication and authorization",
            checks=[
                "Check session handling",
                "Verify credential storage",
                "Review token management"
            ],
            status="pending"
        )
        
        print("  ✓ Coverage ledger created: coverage-ledger.json")
    
    def save_findings(self, output_path: Path):
        """Save findings to JSON file."""
        findings_data = []
        for finding in self.findings:
            evidence_data = [
                {
                    "file_path": e.file_path,
                    "line_number": e.line_number,
                    "code_snippet": e.code_snippet,
                    "confidence": e.confidence
                }
                for e in finding.source_evidence
            ]

            finding_data = {
                "type": "Finding",
                "id": finding.id,
                "verdict": finding.verdict.name.lower(),
                "description": finding.description,
                "cwe_ids": finding.cwe_ids,
                "severity": finding.severity,
                "source_evidence": evidence_data,
                "observed_behavior": finding.observed_behavior,
                "remediation": finding.remediation,
                "initial_discovery": finding.initial_discovery,
                "validation_attempts": finding.validation_attempts,
                "verified_by": finding.verified_by
            }
            findings_data.append(finding_data)

        with open(output_path, 'w') as f:
            json.dump(findings_data, f, indent=2)

    def save_coverage_ledger(self, output_path: Path):
        """Save coverage ledger to JSON file."""
        ledger_data = {}
        for category, entry in self.coverage_ledger.items():
            ledger_data[category] = {
                "category": entry.category,
                "description": entry.description,
                "checks": entry.checks,
                "status": entry.status,
                "evidence_files": list(entry.evidence_files)
            }

        with open(output_path, 'w') as f:
            json.dump(ledger_data, f, indent=2)


class FindingsValidator:
    """Helper class for findings validation."""

    @staticmethod
    def validate_findings_json(findings_path: Path, schema_path: Path = None) -> bool:
        """
        Validate findings.json against report-schema.json.
        Zero-dependency validator used in Phase 4 and Phase 5.
        """
        import json

        # Read findings
        with open(findings_path) as f:
            findings = json.load(f)

        # Simplified schema validation
        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                print(f"Validation error at {i}: Finding must be an object")
                return False

            if "type" not in finding or finding["type"] != "Finding":
                print(f"Validation error at {i}: Missing or invalid type")
                return False

            if "verdict" not in finding:
                print(f"Validation error at {i}: Missing verdict")
                return False
            elif finding["verdict"] not in ["confirmed", "needs_validation", "rejected"]:
                print(f"Validation error at {i}: Invalid verdict: {finding['verdict']}")
                return False

            if "cwe_ids" not in finding or not isinstance(finding["cwe_ids"], list):
                print(f"Validation error at {i}: Invalid or missing cwe_ids")
                return False

            required_fields = {"id", "description", "cwe_ids", "initial_discovery", "validation_attempts"}
            missing = required_fields - set(finding.keys())
            if missing:
                print(f"Validation error at {i}: Missing fields: {missing}")
                return False

        return True


def main():
    """Main entry point for the security audit skill."""
    print("=" * 70)
    print("Security Audit Skill - Dummy Implementation")
    print("=" * 70)
    print()
    print("Orchestrates isolated agents through:")
    print("  1. Reconnaissance - mapping architecture")
    print("  2. Coverage-led Hunting - finding gaps")
    print("  3. Candidate Validation - adversarial verification")
    print("  4. Structured Output - JSON findings")
    print("  5. Independent Record Verification")
    print("  6. Target-neutral Reporting")
    print()
    print("=" * 70)

    # Initialize with a sample configuration
    config = AuditConfig(
        execution_dir=Path("."),
        output_root=Path("~/security-audit-skill/demo-project/run-1")
    )
    
    skill = SecurityAuditSkill(config)
    
    # Example: Run a reconnaissance phase
    skill.run()
    
    # Example: Create and save a finding
    source_evidence = [
        SourceEvidence(
            file_path="src/auth.py",
            line_number=42,
            code_snippet='password = request.get_param("password")',
            confidence=0.8
        )
    ]
    
    # Try a REJECTED finding first (no evidence)
    rejected_finding = skill.discover_vulnerability(
        description="Too permissive password handling",
        cwe_ids=[287],
        source_files=[],
        verdict_type=Verdict.REJECTED,
        vulnerability_type="authentication",
        recommended_fix="Implement properly hashed password storage"
    )
    print(f"Created finding: {rejected_finding.id} - {rejected_finding.description}")
    
    # Create a CONFIRMED finding after validation
    confirmed_finding = skill.discover_vulnerability(
        description="SQL injection in user query",
        cwe_ids=[89],
        source_files=[
            SourceEvidence(
                file_path="src/api/users.py",
                line_number=15,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
                confidence=0.95
            )
        ],
        verdict_type=Verdict.CONFIRMED,
        vulnerability_type="sql_injection",
        recommended_fix="Use parameterized queries"
    )
    confirmed_finding.severity = "HIGH"
    confirmed_finding.observed_behavior = "Unauthenticated user can query arbitrary user profiles"
    print(f"Created finding: {confirmed_finding.id} - {confirmed_finding.description}")
    
    # Save findings
    output_dir = Path.home() / "security-audit-skill/sample-project/run-1"
    output_dir.mkdir(parents=True, exist_ok=True)
    skill.save_findings(output_dir / "findings.json")
    skill.save_coverage_ledger(output_dir / "coverage-ledger.json")
    
    print(f"\n✓ Findings saved to: {output_dir}")
    print(f"  - findings.json")
    print(f"  - coverage-ledger.json")


if __name__ == "__main__":
    main()