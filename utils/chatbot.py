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

        # Enhanced cybersecurity topics - check these BEFORE general knowledge
        elif any(word in query_lower for word in ['data poisoning']):
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

        elif any(word in query_lower for word in ['sql injection', 'sql']):
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

        elif any(word in query_lower for word in ['malware']):
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

        elif any(word in query_lower for word in ['firewall']):
            response = """**How Firewalls Protect Networks**

A firewall is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules.

**Types of Firewalls:**
1. **Packet-Filtering Firewalls** - Examine packets and filter based on rules
2. **Stateful Inspection Firewalls** - Track connection states and context
3. **Application-Level Gateways** - Filter traffic at application layer
4. **Next-Generation Firewalls** - Include advanced threat prevention

**Best Practices:**
1. **Default Deny Policy** - Block all traffic by default, allow only what's needed
2. **Regular Rule Reviews** - Update and audit firewall rules regularly
3. **Logging and Monitoring** - Monitor all traffic for suspicious activity
4. **Integration with IDS/IPS** - Combine with intrusion detection systems
5. **Segmentation** - Separate networks to limit lateral movement

**Configuration Tips:**
- Place firewalls at network perimeter
- Use DMZ for public-facing services
- Implement VPN access for remote users
- Regular firmware updates and patches"""

        elif any(word in query_lower for word in ['password']):
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
- Regularly review and update passwords
- Monitor for data breaches involving your accounts"""

        # General knowledge responses - check these AFTER specific topics
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
                
            elif any(topic in query_lower for topic in ['science', 'physics', 'chemistry', 'biology', 'mathematics']):
                response = """**Science & Mathematics**

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
                # General fallback for unknown topics
                response = f"""**Understanding "{query}"**

This is an interesting topic! While I specialize in cybersecurity, I can help with general knowledge questions too.

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
