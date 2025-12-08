// CyberHawk AI Chatbot

class CyberHawkChatbot {
    constructor() {
        this.isOpen = false;
        this.messages = [];
        this.init();
    }

    init() {
        this.createChatbotHTML();
        this.attachEventListeners();
        this.showWelcomeMessage();
    }

    createChatbotHTML() {
        const chatbotHTML = `
            <!-- Chatbot Toggle Button -->
            <div class="chatbot-toggle" id="chatbotToggle">
                <i class="bi bi-robot"></i>
            </div>

            <!-- Chatbot Container -->
            <div class="chatbot-container" id="chatbotContainer">
                <!-- Header -->
                <div class="chatbot-header">
                    <div class="chatbot-header-content">
                        <div class="chatbot-avatar">
                            <i class="bi bi-robot"></i>
                        </div>
                        <div class="chatbot-title">
                            <h4>CyberHawk AI</h4>
                            <p>Ask me anything about CyberHawk</p>
                        </div>
                    </div>
                    <button class="chatbot-close" id="chatbotClose">
                        <i class="bi bi-x"></i>
                    </button>
                </div>

                <!-- Messages Area -->
                <div class="chatbot-messages" id="chatbotMessages">
                    <!-- Messages will appear here -->
                </div>

                <!-- Quick Questions -->
                <div class="quick-questions" id="quickQuestions">
                    <div class="quick-questions-title">Quick Questions:</div>
                    <div class="quick-questions-list">
                        <button class="quick-question" data-question="What is CyberHawk?">What is CyberHawk?</button>
                        <button class="quick-question" data-question="How does IPS work?">How does IPS work?</button>
                        <button class="quick-question" data-question="What is ransomware detection?">Ransomware Detection</button>
                        <button class="quick-question" data-question="How to use reporting?">Reporting Features</button>
                    </div>
                </div>

                <!-- Input Area -->
                <div class="chatbot-input">
                    <input
                        type="text"
                        id="chatbotInput"
                        placeholder="Ask about CyberHawk features..."
                        autocomplete="off"
                    />
                    <button id="chatbotSend">
                        <i class="bi bi-send-fill"></i>
                    </button>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', chatbotHTML);
    }

    attachEventListeners() {
        const toggle = document.getElementById('chatbotToggle');
        const close = document.getElementById('chatbotClose');
        const sendBtn = document.getElementById('chatbotSend');
        const input = document.getElementById('chatbotInput');
        const quickQuestions = document.querySelectorAll('.quick-question');

        toggle.addEventListener('click', () => this.toggleChatbot());
        close.addEventListener('click', () => this.toggleChatbot());
        sendBtn.addEventListener('click', () => this.sendMessage());
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });

        quickQuestions.forEach(btn => {
            btn.addEventListener('click', () => {
                const question = btn.getAttribute('data-question');
                this.sendMessage(question);
            });
        });
    }

    toggleChatbot() {
        this.isOpen = !this.isOpen;
        const container = document.getElementById('chatbotContainer');
        const toggle = document.getElementById('chatbotToggle');

        container.classList.toggle('active');
        toggle.classList.toggle('active');

        if (this.isOpen) {
            document.getElementById('chatbotInput').focus();
        }
    }

    showWelcomeMessage() {
        setTimeout(() => {
            this.addMessage('bot', 'Hello! 👋 I\'m CyberHawk AI, your intelligent security assistant. I can help you understand our Intrusion Prevention System, malware detection, ransomware protection, and reporting features. How can I assist you today?');
        }, 500);
    }

    addMessage(type, content) {
        const messagesContainer = document.getElementById('chatbotMessages');
        const time = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

        const messageHTML = `
            <div class="message ${type}">
                <div class="message-avatar">
                    <i class="bi bi-${type === 'bot' ? 'robot' : 'person-circle'}"></i>
                </div>
                <div>
                    <div class="message-content">${content}</div>
                    <div class="message-time">${time}</div>
                </div>
            </div>
        `;

        messagesContainer.insertAdjacentHTML('beforeend', messageHTML);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    showTypingIndicator() {
        const messagesContainer = document.getElementById('chatbotMessages');
        const typingHTML = `
            <div class="message bot typing-indicator active" id="typingIndicator">
                <div class="message-avatar">
                    <i class="bi bi-robot"></i>
                </div>
                <div class="typing-dots">
                    <span></span>
                    <span></span>
                    <span></span>
                </div>
            </div>
        `;
        messagesContainer.insertAdjacentHTML('beforeend', typingHTML);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    hideTypingIndicator() {
        const indicator = document.getElementById('typingIndicator');
        if (indicator) indicator.remove();
    }

    async sendMessage(predefinedMessage = null) {
        const input = document.getElementById('chatbotInput');
        const message = predefinedMessage || input.value.trim();

        if (!message) return;

        // Add user message
        this.addMessage('user', message);
        input.value = '';

        // Show typing indicator
        this.showTypingIndicator();

        // Send to backend
        try {
            const response = await fetch(MDIR + 'api/chatbot.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message })
            });

            const data = await response.json();

            // Hide typing indicator
            this.hideTypingIndicator();

            if (data.success) {
                this.addMessage('bot', data.response);
            } else {
                this.addMessage('bot', 'Sorry, I encountered an error. Please try again.');
            }
        } catch (error) {
            this.hideTypingIndicator();
            this.addMessage('bot', 'Sorry, I\'m having trouble connecting. Please check your internet connection and try again.');
        }
    }
}

// Initialize chatbot when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new CyberHawkChatbot();
});
