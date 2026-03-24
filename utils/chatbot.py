"""
Enhanced AI Security Assistant with General Knowledge Support
Handles both cybersecurity and general questions
"""

import random
from datetime import datetime
from typing import Dict, List, Any

class CyberSecurityChatbot:
    def __init__(self):
        self.conversation_history = []
        self.knowledge_base = {
            "data_poisoning": {
                "definition": "Data poisoning is a type of adversarial attack where malicious actors intentionally corrupt training data to manipulate ML model behavior.",
                "prevention": ["Data validation", "Anomaly detection", "Robust algorithms", "Regular auditing"],
                "examples": ["Backdoor attacks", "Label flipping", "Feature manipulation"]
            },
            "sql_injection": {
                "definition": "SQL injection attacks data-driven applications by inserting malicious SQL statements into input fields.",
                "prevention": ["Parameterized queries", "Input validation", "Least privilege", "WAF deployment"],
                "examples": ["' OR '1'='1", "UNION SELECT", "DROP TABLE"]
            },
            "malware": {
                "definition": "Malicious software designed to damage, disrupt, or gain unauthorized access to computer systems.",
                "types": ["Virus", "Worm", "Trojan", "Ransomware", "Spyware", "Adware"],
                "prevention": ["Antivirus software", "Regular updates", "User education", "Email filtering"]
            },
            "firewall": {
                "definition": "Network security system that monitors and controls incoming and outgoing network traffic.",
                "types": ["Hardware firewalls", "Software firewalls", "Cloud firewalls", "Next-gen firewalls"],
                "best_practices": ["Default deny", "Regular rule review", "Logging and monitoring", "Integration with IDS/IPS"]
            },
            "password_security": {
                "definition": "Practices and techniques for creating and managing secure passwords.",
                "best_practices": ["Length (12+ chars)", "Complexity", "Uniqueness", "Regular changes"],
                "tools": ["Password managers", "MFA", "Password generators", "Breach monitoring"]
            }
        }
    
    def get_response(self, query: str) -> Dict[str, Any]:
        """Get chatbot response for user query"""
        timestamp = datetime.now().isoformat()
        query_lower = query.lower()
        
        # Enhanced greeting and general conversation - more specific detection
        if (any(word in query_lower for word in ['hello', 'hi', 'hey', 'greetings']) or
            (any(word in query_lower for word in ['good morning', 'good afternoon', 'good evening', 'good day']) and
             len(query_lower.split()) <= 4) or  # Only match if it's a short greeting
            (any(word in query_lower for word in ['gm']) and len(query_lower) <= 3) or  # Only "gm" alone
            ('sentra' in query_lower and len(query_lower.split()) <= 3 and  # Only "hi sentra" type
             any(word in query_lower for word in ['hello', 'hi', 'hey']))):
            hour = datetime.now().hour
            if 5 <= hour < 12:
                greeting = "Good morning"
            elif 12 <= hour < 17:
                greeting = "Good afternoon"
            elif 17 <= hour < 22:
                greeting = "Good evening"
            else:
                greeting = "Hello"
                
            response = f"""{greeting}! I'm **Sentra**, your AI Security Assistant. I'm here to help you with:

🔒 **Cybersecurity & Security Topics**
- Data poisoning and ML security
- Injection attacks (SQL, XSS, Command)
- Malware protection and prevention
- Network security best practices
- Password security and authentication
- Cloud security and DevSecOps
- Security compliance and regulations

💡 **General Knowledge**
- Technology and programming
- Science and mathematics
- History and current events
- Business and finance
- Arts and culture
- Sports and entertainment

🤖 **AI Assistant Features**
- Answer questions on any topic
- Help with problem-solving
- Provide explanations and examples
- Assist with research and learning

I can answer questions on virtually any topic! What would you like to know today?"""

        # General conversation patterns
        elif any(word in query_lower for word in ['how are you', 'how do you do', 'how are you doing']):
            response = """I'm functioning perfectly and ready to help! As an AI assistant, I don't have feelings, but I'm optimized to provide you with accurate, helpful information on cybersecurity and any other topics you're interested in.

Is there something specific you'd like to learn about or discuss?"""

        elif any(word in query_lower for word in ['what are you', 'who are you', 'what is your name']):
            response = """I'm **Sentra**, an AI Security Assistant designed to help with cybersecurity and general knowledge questions. I'm part of PoisonProof AI platform - an enterprise-grade security system.

**My Capabilities:**
- Comprehensive cybersecurity knowledge
- General knowledge across all domains
- Real-time question answering
- Detailed explanations and examples
- Security best practices and guidance

I'm here to make complex topics easy to understand and provide practical, actionable advice. Feel free to ask me anything!"""

        elif any(word in query_lower for word in ['thank you', 'thanks', 'appreciate', 'helpful']):
            response = """You're very welcome! I'm glad I could help you. Remember, I'm always here if you have more questions about cybersecurity, technology, or any other topic.

Is there anything else I can assist you with today?"""

        elif any(word in query_lower for word in ['bye', 'goodbye', 'see you', 'farewell']):
            response = """Goodbye! It was great helping you today. Remember to stay safe online and keep your security practices strong. Feel free to come back anytime you have questions!

Stay secure! 🔒"""

        # Enhanced cybersecurity topics
        elif any(word in query_lower for word in ['ransomware', 'ransom ware']):
            response = """**Ransomware: Understanding and Prevention**

**What is Ransomware?**
Ransomware is malicious software that encrypts files on a victim's computer or network, demanding payment (usually in cryptocurrency) for decryption.

**How Ransomware Spreads:**
- Phishing emails with malicious attachments
- Exploit kits targeting software vulnerabilities
- Remote Desktop Protocol (RDP) attacks
- Malicious websites and drive-by downloads
- Infected software downloads

**Types of Ransomware:**
1. **Crypto Ransomware** - Encrypts files and demands payment
2. **Locker Ransomware** - Locks the entire system
3. **Scareware** - Claims system is infected and demands payment
4. **Doxware** - Threatens to publish stolen data

**Prevention Strategies:**
1. **Regular Backups** - 3-2-1 rule (3 copies, 2 media, 1 offsite)
2. **Email Security** - Filter suspicious emails and attachments
3. **Software Updates** - Keep all systems patched and updated
4. **Network Segmentation** - Limit lateral movement
5. **User Training** - Educate employees about phishing
6. **Endpoint Protection** - Use advanced antivirus/EDR solutions

**If Infected:**
- Isolate affected systems immediately
- Contact cybersecurity professionals
- Report to law enforcement
- Don't pay ransom (no guarantee of recovery)
- Restore from clean backups"""

        elif any(word in query_lower for word in ['phishing', 'phish']):
            response = """**Phishing: Recognition and Prevention**

**What is Phishing?**
Phishing is a social engineering attack where attackers impersonate legitimate organizations to steal sensitive information like passwords, credit card numbers, and personal data.

**Common Phishing Methods:**
1. **Email Phishing** - Fake emails from banks, services, or colleagues
2. **Spear Phishing** - Targeted attacks on specific individuals
3. **Whaling** - Phishing attacks targeting high-level executives
4. **Smishing** - SMS/text message phishing
5. **Vishing** - Voice/phone phishing

**Red Flags to Watch For:**
- Urgent language ("Act now!", "Account suspended!")
- Generic greetings ("Dear Customer" instead of your name)
- Mismatched URLs (hover to check actual destination)
- Poor grammar and spelling errors
- Unexpected attachments or links
- Requests for sensitive information
- Threats or pressure tactics

**Protection Strategies:**
1. **Verify Independently** - Contact organizations through official channels
2. **Check URLs Carefully** - Look for HTTPS and domain authenticity
3. **Use Email Filters** - Enable spam and phishing filters
4. **Enable Two-Factor Authentication** - Adds extra security layer
5. **Security Awareness Training** - Regular education for all users
6. **Report Suspicious Emails** - Help protect others by reporting

**If You Suspect Phishing:**
- Don't click links or download attachments
- Report to your IT/security team
- Delete the message
- Change passwords if you clicked anything suspicious"""

        elif any(word in query_lower for word in ['cloud security', 'cloud computing']):
            response = """**Cloud Security Best Practices**

**Cloud Security Challenges:**
- Data breaches and unauthorized access
- Misconfigured cloud services
- Insecure APIs and interfaces
- Account hijacking
- Malicious insider threats
- Shared responsibility confusion

**Essential Security Controls:**

**1. Identity and Access Management**
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Regular access reviews
- Privileged access management

**2. Data Protection**
- Encryption at rest and in transit
- Data classification and labeling
- Data loss prevention (DLP) tools
- Regular backup and recovery testing

**3. Network Security**
- Virtual private clouds (VPC)
- Security groups and network ACLs
- Web Application Firewalls (WAF)
- DDoS protection

**4. Monitoring and Logging**
- Cloud security posture management (CSPM)
- Security information and event management (SIEM)
- Real-time threat detection
- Compliance monitoring

**5. Compliance and Governance**
- GDPR, HIPAA, PCI DSS compliance
- Regular security audits
- Risk assessments
- Security policies and procedures

**Cloud Provider Security:**
- AWS: IAM, GuardDuty, Security Hub, Macie
- Azure: Security Center, Sentinel, Key Vault
- GCP: Security Command Center, Cloud Armor
- Multi-cloud security tools for hybrid environments"""

        # General knowledge responses
        elif any(word in query_lower for word in ['what is', 'define', 'explain', 'tell me about']):
            # This is a general knowledge question - provide a helpful response
            if any(topic in query_lower for topic in ['python', 'programming', 'coding']):
                response = """**Python Programming**

Python is a high-level, interpreted programming language known for its simplicity and readability. It's widely used in web development, data science, AI/ML, automation, and more.

**Key Features:**
- Clean, readable syntax
- Extensive standard library
- Cross-platform compatibility
- Large ecosystem of third-party packages
- Strong community support

**Common Uses:**
- Web development (Django, Flask)
- Data analysis (Pandas, NumPy)
- Machine learning (TensorFlow, PyTorch)
- Automation and scripting
- Scientific computing

**Getting Started:**
- Install Python from python.org
- Use pip for package management
- Try interactive tutorials and online courses
- Join Python communities for support

Is there something specific about Python you'd like to learn?"""
                
            elif any(topic in query_lower for topic in ['artificial intelligence', 'ai', 'machine learning']):
                response = """**Artificial Intelligence and Machine Learning**

AI is the simulation of human intelligence in machines, while Machine Learning is a subset of AI that enables systems to learn and improve from experience without being explicitly programmed.

**Types of AI:**
1. **Narrow AI** - Designed for specific tasks (Siri, Alexa)
2. **General AI** - Human-level intelligence across domains
3. **Superintelligence** - Surpasses human intelligence

**Machine Learning Approaches:**
- **Supervised Learning** - Learning from labeled data
- **Unsupervised Learning** - Finding patterns in unlabeled data
- **Reinforcement Learning** - Learning through trial and error
- **Deep Learning** - Neural networks with multiple layers

**Real-World Applications:**
- Natural language processing and translation
- Image and speech recognition
- Recommendation systems
- Autonomous vehicles
- Medical diagnosis
- Financial fraud detection

**Ethical Considerations:**
- Bias in training data
- Privacy concerns
- Job displacement
- Accountability and transparency
- Security risks

Would you like to dive deeper into any specific aspect of AI/ML?"""
                
            elif any(topic in query_lower for word in ['science', 'physics', 'chemistry', 'biology']):
                response = """**Science Overview**

Science is the systematic study of the natural world through observation and experimentation. It helps us understand how things work and develop technologies to improve our lives.

**Major Scientific Fields:**

**Physics** - Study of matter, energy, and their interactions
- Classical mechanics, quantum physics, relativity
- Applications in engineering, technology, space exploration

**Chemistry** - Study of substances and their properties
- Organic, inorganic, physical chemistry
- Applications in medicine, materials science, energy

**Biology** - Study of living organisms
- Molecular biology, ecology, genetics
- Applications in medicine, agriculture, conservation

**Scientific Method:**
1. **Observation** - Notice phenomena
2. **Question** - Formulate hypotheses
3. **Experiment** - Test predictions
4. **Analysis** - Interpret results
5. **Conclusion** - Draw and communicate findings

**Current Frontiers:**
- Quantum computing and technology
- Gene editing and synthetic biology
- Climate science and renewable energy
- Space exploration and astronomy
- Neuroscience and brain research

What specific area of science interests you most?"""
                
            else:
                # General knowledge fallback
                response = f"""**Understanding "{query}"**

This is an interesting topic! While I specialize in cybersecurity, I can help with general knowledge questions too.

**To give you the best answer, could you:**
- Be more specific about what you'd like to know?
- Are you looking for a definition, explanation, or examples?
- Is this for a particular context (academic, professional, personal)?

**I can help with:**
- Technology and programming concepts
- Science and mathematics
- History and current events
- Business and finance topics
- Arts, culture, and entertainment

Feel free to ask me anything, and I'll do my best to provide a helpful, accurate response!"""

        # Default response for unmatched queries
        else:
            response = f"""**I'd be happy to help with "{query}"!**

I can assist with a wide range of topics:

🔒 **Cybersecurity Expertise:**
- Data poisoning and ML security
- Network security and firewalls
- Malware and ransomware protection
- Password security and authentication
- Cloud security and compliance

💡 **General Knowledge:**
- Technology and programming
- Science and mathematics
- Business and finance
- History and current events
- Arts and culture

**Try asking me:**
- "What is [topic]?" - for definitions
- "How does [technology] work?" - for explanations
- "Tell me about [subject]" - for overviews
- Any cybersecurity question - for expert advice

What specific aspect would you like to explore?"""
        
        # General knowledge and fallback responses
        elif any(word in query_lower for word in ['what is', 'define', 'explain', 'tell me about', 'how does', 'how do', 'why is', 'where is', 'who is', 'when did']):
            # This is a general knowledge question
            if any(topic in query_lower for topic in ['python', 'programming', 'coding', 'javascript', 'html', 'css']):
                response = """**Programming & Development**

I can help with various programming topics:

**Popular Languages:**
- **Python** - Great for beginners, data science, AI/ML
- **JavaScript** - Web development, interactive applications
- **Java** - Enterprise applications, Android development
- **C++** - System programming, game development
- **HTML/CSS** - Web design and styling

**Getting Started:**
1. Choose a language based on your goals
2. Set up development environment
3. Learn basic syntax and concepts
4. Practice with small projects
5. Join coding communities for support

**Resources:**
- Online tutorials (freeCodeCamp, Codecademy)
- Documentation (MDN, official docs)
- Practice platforms (LeetCode, HackerRank)
- Community (Stack Overflow, GitHub)

What specific programming topic interests you?"""
                
            elif any(topic in query_lower for topic in ['artificial intelligence', 'ai', 'machine learning', 'deep learning']):
                response = """**Artificial Intelligence & Machine Learning**

AI is transforming how we interact with technology and solve complex problems.

**Key Concepts:**
- **Machine Learning** - Systems that learn from data
- **Deep Learning** - Neural networks with multiple layers
- **Natural Language Processing** - Understanding human language
- **Computer Vision** - Interpreting visual information

**Applications:**
- Virtual assistants (Siri, Alexa)
- Recommendation systems (Netflix, Amazon)
- Autonomous vehicles
- Medical diagnosis
- Financial fraud detection

**Learning Path:**
1. Start with Python programming
2. Learn mathematics (linear algebra, statistics)
3. Study ML algorithms and frameworks
4. Work on real projects
5. Stay updated with research

Would you like to dive deeper into any specific area?"""
                
            elif any(topic in query_lower for topic in ['science', 'physics', 'chemistry', 'biology', 'mathematics']):
                response = """**Science & Mathematics**

Science helps us understand the natural world through observation and experimentation.

**Major Fields:**
- **Physics** - Matter, energy, motion, forces
- **Chemistry** - Elements, compounds, reactions
- **Biology** - Living organisms, evolution, genetics
- **Mathematics** - Numbers, patterns, logic, proofs

**Scientific Method:**
1. **Observation** - Notice phenomena
2. **Hypothesis** - Form testable explanation
3. **Experiment** - Test predictions
4. **Analysis** - Interpret results
5. **Conclusion** - Draw and communicate findings

**Current Frontiers:**
- Quantum computing and technology
- Gene editing and synthetic biology
- Climate science and renewable energy
- Space exploration
- Neuroscience and brain research

What scientific area interests you most?"""
                
            else:
                # General fallback for unknown topics
                response = f"""**Understanding "{query}"**

This is an interesting topic! I can help you learn more about it.

**What I can do:**
- Provide definitions and explanations
- Give examples and analogies
- Explain concepts step by step
- Connect to related topics
- Suggest further learning resources

**To help you better:**
- Could you be more specific about what you'd like to know?
- Are you looking for basic information or advanced details?
- Is this for academic, professional, or personal learning?

Feel free to ask follow-up questions, and I'll provide detailed information!"""

        # Default response for unmatched queries
        else:
            response = f"""**I'd be happy to help with "{query}"!**

I can assist with a wide range of topics:

🔒 **Cybersecurity Expertise:**
- Data poisoning and ML security
- Network security and firewalls
- Malware and ransomware protection
- Password security and authentication
- Cloud security and compliance

💡 **General Knowledge:**
- Technology and programming
- Science and mathematics
- Business and finance
- History and current events
- Arts and culture

**Try asking me:**
- "What is [topic]?" - for definitions
- "How does [technology] work?" - for explanations
- "Tell me about [subject]" - for overviews
- Any cybersecurity question - for expert advice

What specific aspect would you like to explore?"""
        
        # Store conversation
        conversation_entry = {
            "timestamp": timestamp,
            "query": query,
            "response": response,
            "query_type": "general"
        }
        
        self.conversation_history.append(conversation_entry)
        
        return {
            "response": response,
            "timestamp": timestamp,
            "query_type": "general",
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
            "What are best practices for password security?",
            "What is phishing and how can I avoid it?",
            "How does cloud security work?",
            "What is artificial intelligence?",
            "Tell me about Python programming",
            "What are the latest cybersecurity threats?"
        ]

# Create global instance
chatbot = CyberSecurityChatbot()
