from pathlib import Path

from parser import LogParser
from rules import DetectionEngine

def main():
    project_root = Path(__file__).resolve().parents[2]
    file_path = project_root / "sample_logs" / "events.json"
    
    parser = LogParser()
    engine = DetectionEngine()
    
    events = parser.parse_events(str(file_path))
    
    if events is None:
        print("[!] Could not load events.")
        return
    
    all_findings = []
    for event in events:
        findings = engine.analyze_events(event)
        all_findings.extend(findings)
        
    
    print(f"[*] Total events processed: {len(events)}")
    print(f"[*] Total findings detected {len(all_findings)}")
    
    for finding in all_findings:
        print(finding)
        
if __name__ == "__main__":
    main()