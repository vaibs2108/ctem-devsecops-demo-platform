import sys
import os

print("Starting import verification check...")

modules_to_test = [
    "app.ui.theme",
    "app.data.synthetic_banner",
    "app.data.generator",
    "app.kpi.engine",
    "app.llm.router",
    "app.workflow.remediation",
    "app.ui.components.auth",
    "app.ui.components.charts",
    "app.ui.components.interactive_demo",
    "app.ui.components.lifecycle_stage",
    "app.ui.dashboards.executive",
    "app.ui.pages.ctem",
    "app.ui.pages.devsecops",
    "app.ui.pages.data_explorer",
    "app.ui.pages.agents_repo",
    "app.ui.pages.settings",
    "app.ui.pages.token_usage",
    "app.ui.pages.observability",
]

failures = 0
for mod in modules_to_test:
    try:
        print(f"Testing {mod}...", end=" ")
        __import__(mod)
        print("SUCCESS")
    except Exception as e:
        print("FAILED")
        import traceback
        traceback.print_exc()
        failures += 1

if failures > 0:
    print(f"\nVerification finished with {failures} failures.")
    sys.exit(1)
else:
    print("\nAll core modules imported successfully! Codebase structural integrity verified.")
    sys.exit(0)
