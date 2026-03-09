"""
AI Chatbot Utility for PoisonProof AI
Provides cybersecurity and general knowledge assistance
"""

import json
import random
import re
from datetime import datetime
from typing import Dict, List, Any

class CyberSecurityChatbot:
    """AI Chatbot specialized in cybersecurity and general knowledge"""
    
    def __init__(self):
        self.conversation_history = []
        self.knowledge_base = self._initialize_knowledge_base()
        
    def _initialize_knowledge_base(self) -> Dict[str, Any]:
        """Initialize the chatbot knowledge base"""
        return {
            "cybersecurity_topics": {
                "data_poisoning": {
                    "definition": "Data poisoning is a type of adversarial attack where malicious actors intentionally corrupt training data to manipulate ML model behavior.",
                    "prevention": [
                        "Use data validation and sanitization",
                        "Implement anomaly detection on training data",
                        "Use robust machine learning algorithms",
                        "Regular model auditing and validation"
                    ],
                    "detection_methods": [
                        "Statistical analysis of data distributions",
                        "Outlier detection algorithms",
                        "Cross-validation with trusted datasets",
                        "Behavioral analysis of model predictions"
                    ]
                },
                "injection_attacks": {
                    "sql_injection": {
                        "definition": "SQL injection is a code injection technique that attacks data-driven applications by inserting malicious SQL statements.",
                        "examples": [
                            "' OR '1'='1",
                            "UNION SELECT username, password FROM users",
                            "'; DROP TABLE users; --"
                        ],
                        "prevention": [
                            "Use parameterized queries/prepared statements",
                            "Input validation and sanitization",
                            "Least privilege database access",
                            "Web Application Firewall (WAF)"
                        ]
                    },
                    "xss": {
                        "definition": "Cross-Site Scripting (XSS) attacks inject malicious scripts into web pages viewed by other users.",
                        "types": ["Stored XSS", "Reflected XSS", "DOM-based XSS"],
                        "prevention": [
                            "Input validation and output encoding",
                            "Content Security Policy (CSP)",
                            "HttpOnly cookies",
                            "X-XSS-Protection headers"
                        ]
                    }
                },
                "malware": {
                    "types": [
                        "Virus", "Worm", "Trojan", "Ransomware", 
                        "Spyware", "Adware", "Rootkit", "Botnet"
                    ],
                    "protection": [
                        "Install reputable antivirus software",
                        "Keep systems and software updated",
                        "Regular backups",
                        "User education and awareness",
                        "Network segmentation"
                    ]
                },
                "network_security": {
                    "firewalls": "Network security systems that monitor and control incoming/outgoing network traffic",
                    "vpn": "Virtual Private Network creates encrypted connections for secure communication",
                    "intrusion_detection": "Systems that monitor network traffic for suspicious activities"
                }
            },
            "general_responses": {
                "greetings": [
                    "Hello! I'm your cybersecurity assistant. How can I help you today?",
                    "Hi there! I can help with cybersecurity questions and general knowledge. What's on your mind?",
                    "Greetings! I'm here to assist with security topics and more. Ask me anything!"
                ],
                "goodbyes": [
                    "Stay safe online! Feel free to come back if you have more questions.",
                    "Goodbye! Remember to keep your systems updated and secure.",
                    "Until next time! Stay cyber-aware and protected."
                ],
                "capabilities": [
                    "I can help with: cybersecurity concepts, data poisoning, injection attacks, malware protection, network security, and general knowledge questions.",
                    "My expertise includes: AI security, threat detection, prevention strategies, and much more.",
                    "I specialize in cybersecurity but can also assist with general technology and security-related questions."
                ]
            }
        }
    
    def _classify_query(self, query: str) -> str:
        """Classify the user query to determine response type"""
        query_lower = query.lower()
        
        # Check for greetings
        if any(word in query_lower for word in ['hello', 'hi', 'hey', 'greetings']):
            return 'greeting'
        
        # Check for goodbyes
        if any(word in query_lower for word in ['bye', 'goodbye', 'see you', 'farewell']):
            return 'goodbye'
        
        # Check for capabilities
        if any(word in query_lower for word in ['what can you do', 'help', 'capabilities', 'features']):
            return 'capabilities'
        
        # Enhanced cybersecurity keywords detection
        cyber_keywords = [
            'cybersecurity', 'security', 'hack', 'attack', 'malware', 'virus',
            'data poisoning', 'poisoning', 'injection', 'sql', 'xss', 'firewall', 'vpn',
            'encryption', 'password', 'phishing', 'ransomware', 'trojan', 'worm',
            'botnet', 'spyware', 'adware', 'rootkit', 'keylogger', 'ddos',
            'network', 'threat', 'vulnerability', 'breach', 'incident', 'forensics',
            'penetration', 'authentication', 'authorization', 'zero day', 'exploit',
            'backdoor', 'malicious', 'protect', 'prevent', 'detect', 'secure'
        ]
        
        # Check for partial matches and word boundaries
        for keyword in cyber_keywords:
            if keyword in query_lower:
                return 'cybersecurity'
        
        # Check for common cybersecurity question patterns
        cyber_patterns = [
            'how to prevent', 'how to protect', 'how to detect', 'how to secure',
            'what is', 'what are', 'how does', 'why is', 'best practices',
            'common types', 'types of', 'examples of', 'how to avoid'
        ]
        
        cyber_topic_words = [
            'data', 'machine learning', 'ml', 'ai', 'model', 'training', 'dataset',
            'database', 'web', 'application', 'system', 'network', 'computer'
        ]
        
        # If query contains cybersecurity patterns AND topic words, classify as cybersecurity
        has_cyber_pattern = any(pattern in query_lower for pattern in cyber_patterns)
        has_topic_words = any(word in query_lower for word in cyber_topic_words)
        
        if has_cyber_pattern and has_topic_words:
            return 'cybersecurity'
        
        return 'general'
    
    def _search_knowledge_base(self, query: str) -> Dict[str, Any]:
        """Search knowledge base for relevant information"""
        query_lower = query.lower()
        results = {}
        
        # Enhanced search for cybersecurity topics
        for topic, data in self.knowledge_base["cybersecurity_topics"].items():
            # Direct topic match
            if topic.replace('_', ' ') in query_lower or topic in query_lower:
                results[topic] = data
                continue
            
            # Search in subtopics and content
            if isinstance(data, dict):
                for subtopic, subdata in data.items():
                    # Subtopic match
                    if subtopic.replace('_', ' ') in query_lower or subtopic in query_lower:
                        results[f"{topic}_{subtopic}"] = subdata
                        continue
                    
                    # Content-based search for definitions and text
                    if isinstance(subdata, dict):
                        # Search in definition
                        if "definition" in subdata:
                            def_lower = subdata["definition"].lower()
                            if any(word in def_lower for word in query_lower.split() if len(word) > 2):
                                results[f"{topic}_{subtopic}"] = subdata
                                continue
                        
                        # Search in prevention methods
                        if "prevention" in subdata:
                            for method in subdata["prevention"]:
                                if any(word in method.lower() for word in query_lower.split() if len(word) > 2):
                                    results[f"{topic}_{subtopic}"] = subdata
                                    break
                        
                        # Search in examples
                        if "examples" in subdata:
                            for example in subdata["examples"]:
                                if any(word in example.lower() for word in query_lower.split() if len(word) > 2):
                                    results[f"{topic}_{subtopic}"] = subdata
                                    break
                    
                    # Simple text search
                    elif isinstance(subdata, str):
                        if any(word in subdata.lower() for word in query_lower.split() if len(word) > 2):
                            results[f"{topic}_{subtopic}"] = subdata
                            continue
            
            # Topic-level content search
            elif isinstance(data, dict):
                if "definition" in data:
                    def_lower = data["definition"].lower()
                    if any(word in def_lower for word in query_lower.split() if len(word) > 2):
                        results[topic] = data
                        continue
        
        return results
    
    def _generate_cybersecurity_response(self, query: str, search_results: Dict[str, Any]) -> str:
        """Generate response for cybersecurity queries"""
        if not search_results:
            return self._generate_fallback_cyber_response(query)
        
        responses = []
        
        for key, data in search_results.items():
            if isinstance(data, dict) and "definition" in data:
                responses.append(f"**{key.replace('_', ' ').title()}**: {data['definition']}")
                
                if "prevention" in data:
                    responses.append("\n**Prevention Methods**:")
                    for i, method in enumerate(data["prevention"], 1):
                        responses.append(f"{i}. {method}")
                
                if "examples" in data:
                    responses.append("\n**Examples**:")
                    for example in data["examples"]:
                        responses.append(f"• `{example}`")
                
                if "types" in data:
                    responses.append(f"\n**Types**: {', '.join(data['types'])}")
        
        if responses:
            return "\n\n".join(responses)
        
        return self._generate_fallback_cyber_response(query)
    
    def _generate_fallback_cyber_response(self, query: str) -> str:
        """Generate fallback response for cybersecurity queries"""
        fallback_responses = [
            f"That's an interesting cybersecurity question about '{query}'. While I don't have specific information on that exact topic, I recommend consulting official security documentation or cybersecurity frameworks for detailed guidance.",
            f"I understand you're asking about {query}. For the most current information on this security topic, I suggest checking resources like NIST guidelines, OWASP documentation, or CIS benchmarks.",
            f"Regarding {query}, this appears to be a security-related topic. For comprehensive and up-to-date information, please refer to authoritative cybersecurity sources and best practices."
        ]
        return random.choice(fallback_responses)
    
    def _generate_general_response(self, query: str) -> str:
        """Generate response for general knowledge queries"""
        general_responses = [
            f"That's an interesting question about '{query}'. While I specialize in cybersecurity, I can suggest exploring reliable sources for comprehensive information on this topic.",
            f"I understand you're asking about {query}. My primary expertise is in cybersecurity and AI security, but I recommend checking authoritative sources for detailed information on this subject.",
            f"Regarding {query}, this falls outside my main cybersecurity specialization. For accurate information, I'd recommend consulting subject matter experts or reliable reference materials."
        ]
        return random.choice(general_responses)
    
    def get_response(self, query: str) -> Dict[str, Any]:
        """Get chatbot response for user query"""
        timestamp = datetime.now().isoformat()
        query_lower = query.lower()
        
        # Direct keyword-based responses
        if any(word in query_lower for word in ['hello', 'hi', 'hey', 'greetings']):
            response = """Hello! I'm **Sentra**, your AI Security Assistant. I can help you with:

🔒 **Data poisoning and ML security**
💉 **Injection attacks (SQL, XSS, Command)**
🦠 **Malware protection and prevention**
🛡️ **Network security best practices**
🔐 **General cybersecurity questions**

Feel free to ask me anything about cybersecurity! What would you like to know?"""

        elif "data poisoning" in query_lower:
            response = """**Data Poisoning in Machine Learning**

Data poisoning is a type of adversarial attack where malicious actors intentionally corrupt training data to manipulate ML model behavior.

**How it works:**
- Attackers insert malicious samples into training datasets
- These samples are designed to manipulate model decision boundaries
- Can cause models to make incorrect predictions or specific targeted misclassifications

**Prevention Methods:**
1. **Data Validation** - Rigorously validate and sanitize all training data
2. **Anomaly Detection** - Use statistical methods to detect outliers in training data
3. **Robust Algorithms** - Use ML models that are resistant to adversarial training
4. **Regular Auditing** - Continuously monitor model behavior for anomalies
5. **Trusted Data Sources** - Verify the integrity of data sources

**Detection Techniques:**
- Statistical analysis of data distributions
- Cross-validation with trusted datasets
- Behavioral analysis of model predictions
- Outlier detection algorithms"""

        elif "sql injection" in query_lower or "sql" in query_lower:
            response = """**SQL Injection Attacks**

SQL injection is a code injection technique that attacks data-driven applications by inserting malicious SQL statements into input fields.

**Common Examples:**
- `' OR '1'='1` - Bypasses authentication
- `UNION SELECT username, password FROM users` - Extracts data
- `'; DROP TABLE users; --` - Deletes data

**Prevention Methods:**
1. **Parameterized Queries** - Use prepared statements instead of string concatenation
2. **Input Validation** - Validate and sanitize all user inputs
3. **Least Privilege** - Database accounts should have minimal necessary permissions
4. **Web Application Firewall** - Deploy WAF to filter malicious requests
5. **ORM Frameworks** - Use Object-Relational Mapping tools that handle SQL safely

**Best Practices:**
- Never trust user input
- Use whitelist validation instead of blacklist
- Implement proper error handling that doesn't reveal database structure"""

        elif "malware" in query_lower:
            response = """**Common Types of Malware**

**1. Virus**
- Self-replicating code that attaches to legitimate programs
- Spreads when infected programs are executed

**2. Worm**
- Standalone malware that replicates across networks
- Doesn't need human interaction to spread

**3. Trojan Horse**
- Disguises as legitimate software
- Creates backdoors for attackers

**4. Ransomware**
- Encrypts files and demands payment for decryption
- Can spread through phishing emails and exploit kits

**5. Spyware**
- Secretly monitors user activity
- Steals sensitive information like passwords and financial data

**6. Adware**
- Displays unwanted advertisements
- Can track browsing habits

**7. Rootkit**
- Hides its existence from operating systems
- Provides privileged access to attackers

**8. Botnet**
- Network of infected computers controlled by attacker
- Used for DDoS attacks and spam campaigns"""

        elif "firewall" in query_lower:
            response = """**How Firewalls Protect Networks**

A firewall is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules.

**Protection Mechanisms:**
1. **Packet Filtering** - Examines data packets and blocks suspicious ones
2. **Stateful Inspection** - Tracks active connections and context
3. **Proxy Service** - Acts as intermediary between internal and external networks
4. **Deep Packet Inspection** - Analyzes packet contents for threats

**Types of Firewalls:**
- **Hardware Firewalls** - Physical devices protecting entire networks
- **Software Firewalls** - Programs installed on individual computers
- **Cloud Firewalls** - Virtual firewalls for cloud environments

**Key Benefits:**
- Prevents unauthorized access to private networks
- Blocks malicious traffic and cyber attacks
- Enforces security policies
- Logs network activity for monitoring
- Isolates network segments for added security

**Best Practices:**
- Regularly update firewall rules
- Monitor firewall logs for suspicious activity
- Use multiple layers (defense in depth)"""

        elif "xss" in query_lower or "cross-site scripting" in query_lower:
            response = """**Cross-Site Scripting (XSS)**

XSS attacks inject malicious scripts into web pages viewed by other users, allowing attackers to steal sensitive information or hijack user sessions.

**Types of XSS:**
1. **Stored XSS** - Malicious script permanently stored on target server
2. **Reflected XSS** - Script reflected off server to victim's browser
3. **DOM-based XSS** - Vulnerability exists in client-side code

**Common Attack Vectors:**
- Search bars that don't sanitize input
- Comment sections without proper validation
- User profile fields
- URL parameters

**Prevention Methods:**
1. **Input Validation** - Validate all user input on server-side
2. **Output Encoding** - Encode data before displaying to users
3. **Content Security Policy** - Restrict which scripts can execute
4. **HttpOnly Cookies** - Prevent JavaScript from accessing cookies
5. **X-XSS-Protection Header** - Enable browser XSS protection

**Best Practices:**
- Never trust user input
- Use modern frameworks with built-in XSS protection
- Regularly update dependencies and libraries"""

        elif "password" in query_lower:
            response = """**How to Create Strong Passwords**

**Password Best Practices:**

1. **Length Matters**
   - Minimum 12-16 characters
   - Longer passwords are exponentially harder to crack

2. **Complexity**
   - Use uppercase and lowercase letters
   - Include numbers and special characters
   - Avoid common patterns

3. **Uniqueness**
   - Use different passwords for each account
   - Never reuse passwords across services

4. **Memorable but Secure**
   - Use passphrases (correct horse battery staple)
   - Consider password managers
   - Avoid personal information

**Examples of Strong Passwords:**
- `Tr@inB4tterySt4ple!2024`
- `C0ffee-M@ker#Sunrise`
- `PurpleElephant$Dances@Midnight`

**Password Management:**
- Use reputable password managers (1Password, Bitwarden)
- Enable two-factor authentication everywhere possible
- Change passwords immediately after security breaches
- Never share passwords via email or text

**What to Avoid:**
- Dictionary words
- Personal information (birthdays, names)
- Sequential patterns (123456, qwerty)
- Substitutions only (P@ssword1)"""

        else:
            response = self._generate_fallback_cyber_response(query)
        
        # Store conversation
        conversation_entry = {
            "timestamp": timestamp,
            "query": query,
            "response": response,
            "query_type": "cybersecurity"
        }
        
        self.conversation_history.append(conversation_entry)
        
        return {
            "response": response,
            "timestamp": timestamp,
            "query_type": "cybersecurity",
            "conversation_id": len(self.conversation_history)
        }
    
    def get_conversation_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent conversation history"""
        return self.conversation_history[-limit:]
    
    def clear_history(self):
        """Clear conversation history"""
        self.conversation_history = []
    
    def get_suggested_questions(self) -> List[str]:
        """Get suggested questions for users"""
        return [
            "What is data poisoning in machine learning?",
            "How can I prevent SQL injection attacks?",
            "What are the common types of malware?",
            "How does a firewall protect my network?",
            "What is cross-site scripting (XSS)?",
            "How do I create strong passwords?",
            "What is ransomware and how to prevent it?",
            "What are the best practices for cybersecurity?"
        ]

# Global chatbot instance
chatbot = CyberSecurityChatbot()
