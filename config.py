import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent

# Anthropic
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# Models
MODEL_PARSE   = "claude-haiku-4-5-20251001"   # tool output parsing
MODEL_REASON  = "claude-sonnet-4-6"            # agent reasoning, reports
MODEL_DEEP    = "claude-opus-4-7"              # attack chains, adversarial

# ARGUS behaviour
MAX_RPS           = int(os.getenv("ARGUS_MAX_RPS", 30))
DEFAULT_TIMEOUT   = int(os.getenv("ARGUS_DEFAULT_TIMEOUT", 300))
LOG_LEVEL         = os.getenv("ARGUS_LOG_LEVEL", "INFO")

# Paths
DATA_DIR          = BASE_DIR / "data"
SKILLS_DIR        = BASE_DIR / "skills"
PROMPTS_DIR       = BASE_DIR / "prompts"
TEMPLATES_DIR     = BASE_DIR / "templates"
PAYLOAD_DIR       = DATA_DIR / "payload_knowledge"
SESSION_DB        = DATA_DIR / "sessions.db"

# External APIs
SHODAN_API_KEY         = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY     = os.getenv("VIRUSTOTAL_API_KEY", "")
CENSYS_API_ID          = os.getenv("CENSYS_API_ID", "")
CENSYS_API_SECRET      = os.getenv("CENSYS_API_SECRET", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")

# Metasploit
MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "127.0.0.1")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", 55553))
MSF_RPC_PASS = os.getenv("MSF_RPC_PASS", "")

# BloodHound / Neo4j
NEO4J_URI  = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "")

# OWASP ZAP
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
ZAP_HOST    = os.getenv("ZAP_HOST", "127.0.0.1")
ZAP_PORT    = int(os.getenv("ZAP_PORT", 8080))

# voicetest.dev
VOICETEST_API_KEY = os.getenv("VOICETEST_API_KEY", "")
