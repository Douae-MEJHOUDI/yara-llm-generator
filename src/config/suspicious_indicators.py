"""
Suspicious Indicators Configuration
Based on malware research papers and established YARA rule patterns

"""

# Suspicious API calls commonly used by malware
SUSPICIOUS_API_CALLS = [
    # Process/Thread Manipulation
    "CreateRemoteThread",
    "NtCreateThread",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "CreateThread",
    "QueueUserAPC",

    # Memory Operations (Code Injection)
    "VirtualAllocEx",
    "VirtualAlloc",
    "WriteProcessMemory",
    "NtWriteVirtualMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",

    # Process Operations
    "CreateProcessInternalW",
    "CreateProcessW",
    "ShellExecuteExW",
    "WinExec",
    "system",

    # Hooks and Keylogging
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetAsyncKeyState",
    "GetKeyState",
    "GetKeyboardState",

    # Network/Download
    "URLDownloadToFileW",
    "URLDownloadToFileA",
    "InternetOpenA",
    "InternetOpenW",
    "InternetOpenUrlA",
    "InternetReadFile",
    "HttpSendRequestA",
    "HttpSendRequestW",

    # Anti-Analysis
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
    "OutputDebugStringA",

    # Context Manipulation
    "NtSetContextThread",
    "SetThreadContext",
    "NtGetContextThread",
    "GetThreadContext",

    # Registry Manipulation
    "RegSetValueExA",
    "RegSetValueExW",
    "RegCreateKeyExA",
    "RegCreateKeyExW",
    "RegDeleteValueA",
    "RegDeleteValueW",
]

# Registry keys commonly used for persistence
SUSPICIOUS_REGISTRY_PATTERNS = [
    # Auto-start locations
    "\\CurrentVersion\\Run",
    "\\CurrentVersion\\RunOnce",
    "\\CurrentVersion\\RunServices",
    "\\CurrentVersion\\RunServicesOnce",

    # Startup and Logon
    "\\Winlogon\\Shell",
    "\\Winlogon\\Userinit",
    "\\Winlogon\\Notify",

    # Policies (often used to hide malware)
    "\\CurrentVersion\\Policies\\Explorer",
    "\\Policies\\System",

    # Service-related
    "\\CurrentControlSet\\Services",
    "\\ControlSet001\\Services",

    # Image File Execution Options (debugger hijacking)
    "\\Image File Execution Options",

    # Browser hijacking
    "\\Internet Explorer\\Main",
    "\\SearchScopes",

    # Shell extensions
    "\\ShellIconOverlayIdentifiers",
    "\\Shell Extensions\\Approved",
]

# Suspicious file paths
SUSPICIOUS_FILE_PATHS = [
    "\\AppData\\Roaming",
    "\\AppData\\Local\\Temp",
    "\\Users\\Public",
    "\\ProgramData",
    "\\Windows\\Temp",
    "\\Start Menu\\Programs\\Startup",
    "%TEMP%",
    "%APPDATA%",
]

# Common C2 ports
SUSPICIOUS_PORTS = [
    1337,  # Common backdoor
    4444,  # Metasploit default
    5555,  # Common trojan
    6666,  # IRC bot
    6667,  # IRC
    8080,  # HTTP proxy
    8443,  # HTTPS alternative
    31337, # Elite/backdoor
]

# Suspicious network patterns
SUSPICIOUS_NETWORK_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Raw IP addresses (often malicious)
    r'[a-z0-9]{20,}\.com',  # Very long random domains (DGA)
    r'\.top$',  # Suspicious TLDs often used by malware
    r'\.tk$',
    r'\.ml$',
    r'\.ga$',
]

# Mutex patterns (for malware identification)
SUSPICIOUS_MUTEX_PATTERNS = [
    "Global\\",
    "Local\\",
    r"[A-F0-9]{32}",  # MD5-like hex strings
    r"[A-Z0-9]{8}-[A-Z0-9]{4}",  # Random patterns
]

# Scoring weights for feature importance
FEATURE_WEIGHTS = {
    "api_call": 1.0,
    "registry_persistence": 2.0,
    "process_injection": 3.0,
    "anti_analysis": 2.5,
    "network_activity": 1.5,
    "file_operation": 1.0,
    "mutex": 1.5,
}

# Categories for behavior classification
BEHAVIOR_CATEGORIES = {
    "persistence": ["Run", "RunOnce", "Startup", "Service"],
    "process_injection": ["CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"],
    "keylogging": ["SetWindowsHookEx", "GetAsyncKeyState"],
    "network": ["URLDownloadToFile", "InternetOpen", "HttpSendRequest"],
    "anti_analysis": ["IsDebuggerPresent", "CheckRemoteDebugger"],
    "code_execution": ["CreateProcess", "ShellExecute", "WinExec"],
}
