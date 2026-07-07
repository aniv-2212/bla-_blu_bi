document.addEventListener('DOMContentLoaded', () => {
    const menuToggle = document.getElementById('menuToggle');
    const navMenu = document.getElementById('navMenu');
    const menuLinks = document.querySelectorAll('.nav-menu a');
    const sections = document.querySelectorAll('.content-section');
    
    // Select the new layout wrappers so we can toggle them alongside the sections
    const dashboardGrid = document.querySelector('.dashboard-grid');

    // Toggle Sidebar Drawer panel open/close
    menuToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        navMenu.classList.toggle('active');
    });

    // Handle Panel Routing switches
    menuLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            const targetId = link.getAttribute('data-target');

            // If there's no data-target (like for index.html link), skip JS routing control entirely
            if (!targetId) return;

            e.preventDefault();

            // Hide inactive components
            sections.forEach(sec => sec.classList.remove('active'));

            // Display requested element block
            const targetSection = document.getElementById(targetId);
            if (targetSection) {
                targetSection.classList.add('active');
            }

            // CORE FIX: Only show the side-panel components if the "URL Scanner" is active
            if (targetId === 'url-scanner') {
                if (dashboardGrid) {
                    // Restores grid layout configuration
                    dashboardGrid.style.display = 'grid'; 
                }
            } else {
                if (dashboardGrid) {
                    // Completely clean space for regular pages (like "About")
                    dashboardGrid.style.display = 'block'; 
                }
            }

            // Slide out view window collapse action
            navMenu.classList.remove('active');
        });
    });

    // Close sidebar if clicking outside the sidebar block area
    document.addEventListener('click', (e) => {
        if (!navMenu.contains(e.target) && e.target !== menuToggle) {
            navMenu.classList.remove('active');
        }
    });
});

// --- REDIRECTION TO DASHBOARD LOGIC ---
document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scanBtn');
    const urlInput = document.getElementById('urlInput');

    if (scanBtn && urlInput) {
        scanBtn.addEventListener('click', () => {
            const urlToScan = urlInput.value.trim();

            if (!urlToScan) {
                alert("Please paste a valid URL to analyze.");
                return;
            }

            // Encodes the string properly and redirects to your dashboard page
            window.location.href = `dashboard_url.html?url=${encodeURIComponent(urlToScan)}`;
        });

        // Also allow pressing "Enter" in the input box to trigger the scan
        urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                scanBtn.click();
            }
        });
    }
});