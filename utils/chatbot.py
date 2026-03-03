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
        
        # Check for cybersecurity topics
        cyber_keywords = [
            'cybersecurity', 'security', 'hack', 'attack', 'malware', 'virus',
            'data poisoning', 'injection', 'sql', 'xss', 'firewall', 'vpn',
            'encryption', 'password', 'phishing', 'ransomware', 'trojan'
        ]
        
        if any(keyword in query_lower for keyword in cyber_keywords):
            return 'cybersecurity'
        
        return 'general'
    
    def _search_knowledge_base(self, query: str) -> Dict[str, Any]:
        """Search knowledge base for relevant information"""
        query_lower = query.lower()
        results = {}
        
        # Search in cybersecurity topics
        for topic, data in self.knowledge_base["cybersecurity_topics"].items():
            if topic in query_lower:
                results[topic] = data
                continue
            
            # Search in subtopics
            if isinstance(data, dict):
                for subtopic, subdata in data.items():
                    if subtopic in query_lower:
                        results[f"{topic}_{subtopic}"] = subdata
                    elif isinstance(subdata, dict) and "definition" in subdata:
                        if any(word in query_lower for word in subtopic.split('_')):
                            results[f"{topic}_{subtopic}"] = subdata
        
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
        
        # Classify the query
        query_type = self._classify_query(query)
        
        # Generate response based on type
        if query_type == 'greeting':
            response = random.choice(self.knowledge_base["general_responses"]["greetings"])
        elif query_type == 'goodbye':
            response = random.choice(self.knowledge_base["general_responses"]["goodbyes"])
        elif query_type == 'capabilities':
            response = random.choice(self.knowledge_base["general_responses"]["capabilities"])
        elif query_type == 'cybersecurity':
            search_results = self._search_knowledge_base(query)
            response = self._generate_cybersecurity_response(query, search_results)
        else:
            response = self._generate_general_response(query)
        
        # Store conversation
        conversation_entry = {
            "timestamp": timestamp,
            "query": query,
            "response": response,
            "query_type": query_type
        }
        
        self.conversation_history.append(conversation_entry)
        
        return {
            "response": response,
            "timestamp": timestamp,
            "query_type": query_type,
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
