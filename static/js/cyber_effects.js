// Matrix Binary Rain Effect
class MatrixRain {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        
        this.ctx = this.canvas.getContext('2d');
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        
        this.chars = '01';
        this.fontSize = 14;
        this.columns = this.canvas.width / this.fontSize;
        this.drops = [];
        
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.random() * -100;
        }
        
        this.animate();
    }
    
    draw() {
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.ctx.fillStyle = '#0F0';
        this.ctx.font = this.fontSize + 'px monospace';
        
        for (let i = 0; i < this.drops.length; i++) {
            const text = this.chars[Math.floor(Math.random() * this.chars.length)];
            this.ctx.fillText(text, i * this.fontSize, this.drops[i] * this.fontSize);
            
            if (this.drops[i] * this.fontSize > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            
            this.drops[i]++;
        }
    }
    
    animate() {
        this.draw();
        requestAnimationFrame(() => this.animate());
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.columns = this.canvas.width / this.fontSize;
        this.drops = [];
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.random() * -100;
        }
    }
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    const matrixCanvas = document.getElementById('matrixCanvas');
    if (matrixCanvas) {
        const matrix = new MatrixRain('matrixCanvas');
        window.addEventListener('resize', () => matrix.resize());
    }
});

// Cyber Scan Animation
function startCyberScan(elementId, duration = 3000) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    element.innerHTML = `
        <div class="cyber-scan-wrapper">
            <div class="cyber-scan-line"></div>
            <div class="cyber-scan-text">SCANNING...</div>
        </div>
    `;
    
    setTimeout(() => {
        element.innerHTML = '<div class="cyber-scan-complete">✓ SCAN COMPLETE</div>';
    }, duration);
}

// Glitch Text Effect
function glitchText(element, duration = 100, iterations = 3) {
    const originalText = element.textContent;
    const chars = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
    let count = 0;
    
    const interval = setInterval(() => {
        if (count >= iterations) {
            element.textContent = originalText;
            clearInterval(interval);
            return;
        }
        
        element.textContent = originalText
            .split('')
            .map(char => Math.random() > 0.7 ? chars[Math.floor(Math.random() * chars.length)] : char)
            .join('');
        
        count++;
    }, duration);
}

// Cyber Terminal Typing Effect
async function terminalType(element, text, speed = 50) {
    element.textContent = '';
    for (let i = 0; i < text.length; i++) {
        element.textContent += text[i];
        await new Promise(resolve => setTimeout(resolve, speed));
    }
}

// Neon Glow Pulse
function neonPulse(elements) {
    if (typeof elements === 'string') {
        elements = document.querySelectorAll(elements);
    }
    
    elements.forEach(el => {
        el.style.animation = 'neonPulse 2s ease-in-out infinite';
    });
}

// Export for global use
window.MatrixRain = MatrixRain;
window.startCyberScan = startCyberScan;
window.glitchText = glitchText;
window.terminalType = terminalType;
window.neonPulse = neonPulse;
