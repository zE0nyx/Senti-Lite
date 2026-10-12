import json

FILE_PATH = r"../../sample_logs/events.json"

class LogParser:
    
    def load_events(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as s_file:
                data = json.load(s_file)
                return data
        
        except FileNotFoundError: 
            print("[!] Error: File not found")
            return None
        
        except json.JSONDecodeError:
            print("[!] Error: Invalid JSON formatting found")
            return None


    def detect_encoded_powershell(self, command_string):
        if command_string is None:
            return False
        
        if "-encodedcommand" in command_string.lower():
            return True
        
        return False


    def normalize_event(self, event):
        
        s_event = {
            "event_id" : event.get("EventID"),
            "image" : event.get("Image"),
            "command_line" : event.get("CommandLine"),
            "encoded_powershell_detected" : self.detect_encoded_powershell(event.get("CommandLine"))
        }
        return s_event


    def parse_events(self, file_path):
        events = self.load_events(file_path)
        s_arr = []

        if events is None:
            return None
        
        if not isinstance(events, list):
            print("[!] Error: Expected a list of events")
            return None
        
        for event in events:
            if not isinstance(event, dict):
                return None
            new_event = self.normalize_event(event)
            s_arr.append(new_event)
        
        return s_arr


if __name__ == "__main__":
    parser = LogParser()
    e = parser.parse_events(FILE_PATH)
    print(e)