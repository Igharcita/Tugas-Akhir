// RBA Login System - Scripts

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    
    // Add animation to cards
    const cards = document.querySelectorAll('.hover-zoom');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-5px)';
            this.style.boxShadow = '0 10px 20px rgba(0,0,0,0.2)';
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
            this.style.boxShadow = '0 5px 15px rgba(0,0,0,0.1)';
        });
    });
    
    // Highlight active navigation link
    const currentLocation = window.location.pathname;
    const navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(link => {
        const linkPath = link.getAttribute('href');
        if (linkPath && currentLocation === linkPath) {
            link.classList.add('active');
            link.style.fontWeight = 'bold';
        }
    });
    
    // Fade out alerts automatically after 5 seconds
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Add smooth scrolling to all links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 70,
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Preloader effect (hide after page load)
    const preloader = document.querySelector('.preloader');
    if (preloader) {
        setTimeout(() => {
            preloader.style.opacity = '0';
            setTimeout(() => {
                preloader.style.display = 'none';
            }, 500);
        }, 500);
    }
    
    // Enable mobile dropdown menus to close on click outside
    document.addEventListener('click', function(e) {
        const dropdownMenus = document.querySelectorAll('.dropdown-menu.show');
        dropdownMenus.forEach(menu => {
            if (!menu.contains(e.target) && !menu.previousElementSibling.contains(e.target)) {
                const dropdown = bootstrap.Dropdown.getInstance(menu.previousElementSibling);
                if (dropdown) dropdown.hide();
            }
        });
    });
    
    // Add animation to login status badges
    const badges = document.querySelectorAll('.badge');
    badges.forEach(badge => {
        badge.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.1)';
        });
        
        badge.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
    });
    
    // Format datetime strings to more readable format
    // Menggunakan waktu lokal sistem tanpa konversi zona waktu
    document.querySelectorAll('.format-datetime').forEach(el => {
        const timestamp = el.textContent.trim();
        try {
            // Pemrosesan untuk timestamp MySQL standar
            // Data sudah dalam format waktu lokal sistem
            const date = new Date(timestamp);
            if (!isNaN(date)) {
                // Format: DD/MM/YYYY HH:MM:SS dalam format Indonesia
                const options = { 
                    year: 'numeric', 
                    month: '2-digit', 
                    day: '2-digit', 
                    hour: '2-digit', 
                    minute: '2-digit', 
                    second: '2-digit',
                    hour12: false  // Gunakan format 24-jam
                };
                el.textContent = date.toLocaleString('id-ID', options);
            }
        } catch (e) {
            console.error("Error formatting date:", e);
        }
    });
}); 