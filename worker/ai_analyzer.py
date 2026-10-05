import os
import json
import logging
import time
import redis
from openai import OpenAI

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ai_worker")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
redis_conn = redis.from_url(REDIS_URL)

LLM_API_KEY = os.getenv("LLM_API_KEY")
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api.openai.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o")

client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_API_BASE)

SYSTEM_PROMPT = """
You are an advanced Cyber Security Analyst and WAF engine.
Your task is to deeply analyze HTTP requests against the OWASP Top 10 vulnerabilities.
Key threat vectors:
1. SQL Injection (SQLi)
2. Cross-Site Scripting (XSS)
3. Remote Code Execution (RCE)
4. Path Traversal / LFI / RFI
5. Server-Side Request Forgery (SSRF)
6. Anomalous Headers

RULES:
- Scrutinize every parameter, URL query, body, and header.
- RETURN ONLY a valid JSON object. No markdown formatting.
- FORMAT: {"is_threat": true/false, "threat_type": "None or Vulnerability Name", "reason": "Brief analysis"}
"""

def analyze_with_retry(prompt, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.0
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"LLM API Error (Attempt {attempt+1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)
    return None

def analyze_traffic(request_data):
    client_ip = request_data.get("ip")
    if not client_ip: return
    
    logger.info(f"Analysis started: {client_ip} | Path: {request_data.get('path')} | Query: {request_data.get('query_string')}")
    
    prompt = f"Analyze this HTTP request:\n{json.dumps(request_data, indent=2)}"
    
    result_content = analyze_with_retry(prompt)
    if not result_content:
        logger.error("LLM analysis failed after retries.")
        return
        
    try:
        if result_content.startswith("```json"):
            result_content = result_content.strip("`").replace("json\n", "", 1)
            
        result_json = json.loads(result_content)
        
        if result_json.get("is_threat"):
            threat_type = result_json.get("threat_type", "Unknown")
            reason = result_json.get("reason", "N/A")
            logger.warning(f"THREAT DETECTED! IP: {client_ip} | Type: {threat_type} | Reason: {reason}")
            
            redis_conn.setex(f"blacklist:{client_ip}", 86400, json.dumps(result_json))
        else:
            logger.info(f"Benign Traffic: {client_ip}")
            
    except json.JSONDecodeError:
        logger.error(f"JSON Parse Error. Output: {result_content}")
    except Exception as e:
        logger.error(f"Unexpected Error: {e}")
