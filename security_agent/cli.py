import argparse
import sys
import os
from .main import run_scan

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
        choices=["json", "markdown", "both"],
        default="json",
        help="Report format"
    )
    parser.add_argument(
        "--db-url",
        default=None,
        help="Database URL (optional)"
    )
    
    args = parser.parse_args()
    
    try:
        print(f"[*] Scanning repository: {args.repo_path}")
        print(f"[*] Output format: {args.format}")
        

        os.makedirs(args.output, exist_ok=True)
        
        report = run_scan(
            repo_path=args.repo_path,
            output_dir=args.output,
            report_format=args.format,
            db_url=args.db_url
        )
        
        print(f"\n✅ Scan complete")
        print(f"📊 Score: {report['summary']['score']}")
        print(f"🔴 Findings: {len(report['findings'])}")
        
        exit_code = 0 if report['summary']['status'] == 'PASS' else 1
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()