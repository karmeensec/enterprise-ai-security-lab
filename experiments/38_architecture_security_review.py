
import ast
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "results" / "38_architecture_review.json"

COMPONENTS = {
    "backend/main.py": [
        "chat",
        "rag_chat",
        "evaluate_security",
    ],
    "backend/llm_service.py": [],
    "backend/retrieval_service.py": [],
    "backend/citation_validator.py": [
        "validate_citations",
    ],
    "backend/grounding_validator.py": [],
    "backend/hybrid_grounding.py": [
        "verify_hybrid_grounding",
    ],
    "backend/security_service.py": [],
    "backend/audit_logger.py": [
        "record_security_evaluation",
    ],
    "backend/security_monitor.py": [
        "analyze_security_events",
    ],
    "backend/investigation_service.py": [
        "investigate_alert",
    ],
    "dashboard/router.py": [
        "require_dashboard_login",
    ],
}


def inspect_component(relative_path, expected_functions):
    file_path = ROOT / relative_path

    if not file_path.is_file():
        return {
            "file": relative_path,
            "status": "missing",
            "functions": [],
            "missing_expected_functions": expected_functions,
        }

    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))

    except (OSError, UnicodeError, SyntaxError) as exc:
        return {
            "file": relative_path,
            "status": "inspection_error",
            "error_type": type(exc).__name__,
            "functions": [],
            "missing_expected_functions": expected_functions,
        }

    functions = sorted({
        node.name
        for node in ast.walk(tree)
        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        )
    })

    missing = [
        function
        for function in expected_functions
        if function not in functions
    ]

    return {
        "file": relative_path,
        "status": "present",
        "functions": functions,
        "missing_expected_functions": missing,
    }


def main():
    results = [
        inspect_component(path, functions)
        for path, functions in COMPONENTS.items()
    ]

    missing_files = [
        item["file"]
        for item in results
        if item["status"] == "missing"
    ]

    missing_functions = [
        {
            "file": item["file"],
            "functions": item["missing_expected_functions"],
        }
        for item in results
        if item["missing_expected_functions"]
    ]

    report = {
        "experiment": "38_architecture_security_review",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "review_type": "static_component_inventory",
        "components_checked": len(COMPONENTS),
        "missing_files": missing_files,
        "missing_functions": missing_functions,
        "components": results,
        "limitations": [
            "Function presence does not establish security.",
            "No authentication or authorization flow analysis.",
            "No verification of trust boundaries.",
            "No data-flow or taint analysis.",
            "No runtime adversarial testing.",
        ],
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("=== Experiment 38: Architecture Review ===")
    print("Components checked:", len(COMPONENTS))
    print("Missing files:", len(missing_files))
    print("Missing expected functions:", len(missing_functions))

    for item in missing_functions:
        print(
            "Review function names:",
            item["file"],
            item["functions"],
        )

    print("Report saved:", OUTPUT)
    print("Static inventory completed.")


if __name__ == "__main__":
    main()
