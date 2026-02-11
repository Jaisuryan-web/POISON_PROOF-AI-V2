// PoisonProof AI - Cyber-Lab Theme Main JS

document.addEventListener('DOMContentLoaded', () => {
    // --- 1. Background Particle Animation ---
    const canvas = document.getElementById('cyber-background');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        let particles = [];
        const particleCount = Math.floor(canvas.width / 40);

        class Particle {
            constructor(x, y) {
                this.x = x;
                this.y = y;
                this.size = Math.random() * 2 + 1;
                this.speedY = Math.random() * 1.5 + 0.5;
                this.opacity = Math.random() * 0.5 + 0.2;
            }
            update() {
                this.y += this.speedY;
                if (this.y > canvas.height) {
                    this.y = 0 - this.size;
                    this.x = Math.random() * canvas.width;
                }
            }
            draw() {
                ctx.fillStyle = `rgba(0, 255, 127, ${this.opacity})`;
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                ctx.fill();
            }
        }

        function initParticles() {
            particles = [];
            for (let i = 0; i < particleCount; i++) {
                particles.push(new Particle(Math.random() * canvas.width, Math.random() * canvas.height));
            }
        }

        function animateParticles() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            for (let i = 0; i < particles.length; i++) {
                particles[i].update();
                particles[i].draw();
            }
            requestAnimationFrame(animateParticles);
        }

        initParticles();
        animateParticles();

        window.addEventListener('resize', () => {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            initParticles();
        });
    }

    // --- 2. Loading Overlay Management ---
    const loadingOverlay = document.getElementById('loading-overlay');
    const loadingText = document.getElementById('loading-text');

    window.showLoading = (text = 'Processing...') => {
        if (loadingOverlay) {
            loadingText.textContent = text;
            loadingOverlay.classList.remove('d-none');
        }
    };

    window.hideLoading = () => {
        if (loadingOverlay) {
            loadingOverlay.classList.add('d-none');
        }
    };

    // Show loading overlay on form submission
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', (e) => {
            // Check if the form is for a file upload
            const fileInput = form.querySelector('input[type="file"]');
            if (fileInput && fileInput.files.length > 0) {
                window.showLoading('Uploading and analyzing file...');
            } else if (form.id === 'train-form') {
                 window.showLoading('Initializing model training...');
            }
            else {
                window.showLoading('Processing request...');
            }
        });
    });

    // --- 3. Drag and Drop Upload Area ---
    const uploadArea = document.querySelector('.upload-area');
    if (uploadArea) {
        const fileInput = document.getElementById('file');
        const fileLabel = document.querySelector('label[for="file"]');
        const defaultLabelText = fileLabel.innerHTML;

        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });

        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            if (e.dataTransfer.files.length > 0) {
                fileInput.files = e.dataTransfer.files;
                fileLabel.innerHTML = `<i class="bi bi-file-earmark-check-fill me-2"></i>File selected: ${e.dataTransfer.files[0].name}`;
            }
        });

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                fileLabel.innerHTML = `<i class="bi bi-file-earmark-check-fill me-2"></i>File selected: ${fileInput.files[0].name}`;
            } else {
                fileLabel.innerHTML = defaultLabelText;
            }
        });
    }
    
    // --- 4. Fade-in animations for cards ---
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('fade-in');
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });

    document.querySelectorAll('.cyber-card, .glow-btn').forEach(el => {
        observer.observe(el);
    });
});