class DetectionEngine:
    
    def detect_encoded_payloads(self, command_line):
        if command_line is None:
            return False
        return "-encodedcommand" in command_line.lower()
    
    
    def detect_execution_policy_bypass(self, command_line):
        if command_line is None:
            return False
        return "-executionpolicy bypass" in command_line.lower()
    
    
    def analyze_events(self, event):
        findings = []
        
        if self.detect_encoded_payloads(event.get("command_line")):
            findings.append({
                "event_id": event.get("event_id"),
                "rule_name" : "Encoded Powershell",
                "severity" : "medium",
                "reason" : "CLI contains -EncodedCommand",
            })
        
        if self.detect_execution_policy_bypass(event.get("command_line")):
            findings.append({
                "event_id": event.get("event_id"),
                "rule_name" : "Execution Policy Bypass",
                "severity" : "medium",
                "reason" : "contains -ExecutionPolicy Bypass",
            })
        
        return findings


if __name__ == "__main__":
    engine = DetectionEngine()
    
    event = {
        "event_id": 1,
        "image": "powershell.exe",
        "command_line": "powershell.exe -EncodedCommand abc"
    }
    
    print(engine.analyze_events(event))