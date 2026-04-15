import argparse
import sys
import os
from .main import main as run_main

def main():
    parser = argparse.ArgumentParser(
        description="Security Agent - Multi-scanner security tool"
    )
    parser.add_argument(
        "--repo-path",
        required=True,
        help="Path to the repository to scan"
    )
    parser.add_argument(
        "--output",
        default="reports/",
        help="Output directory for reports"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="json",
        help="Report format"
    )
    
    args = parser.parse_args()
    
    try:
        # Call your existing main function
        run_main()
        print("✅ Scan complete")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()