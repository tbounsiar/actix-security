// Page table of contents generator
(function() {
    // Wait for DOM to be ready
    function ready(fn) {
        if (document.readyState !== 'loading') {
            fn();
        } else {
            document.addEventListener('DOMContentLoaded', fn);
        }
    }

    function createPageToc() {
        // Find the main content area
        const content = document.querySelector('.content main');
        if (!content) return;

        // Find all headings in the content
        const headings = content.querySelectorAll('h2, h3, h4');
        if (headings.length < 2) return; // Don't show TOC for pages with few headings

        // Create the sidetoc container
        const sidetoc = document.createElement('div');
        sidetoc.className = 'sidetoc';

        // Add title
        const title = document.createElement('div');
        title.className = 'sidetoc-title';
        title.textContent = 'On this page';
        sidetoc.appendChild(title);

        // Create the TOC list
        const pagetoc = document.createElement('div');
        pagetoc.className = 'pagetoc';

        headings.forEach(function(heading, index) {
            // Ensure heading has an id
            if (!heading.id) {
                heading.id = 'heading-' + index;
            }

            // Create the TOC link
            const link = document.createElement('a');
            link.href = '#' + heading.id;
            link.textContent = heading.textContent;
            link.className = heading.tagName.toLowerCase();

            link.addEventListener('click', function(e) {
                e.preventDefault();
                const target = document.getElementById(heading.id);
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth' });
                    history.pushState(null, null, '#' + heading.id);
                }
            });

            pagetoc.appendChild(link);
        });

        sidetoc.appendChild(pagetoc);

        // Add to the page
        const wrapper = document.querySelector('.page-wrapper');
        if (wrapper) {
            wrapper.appendChild(sidetoc);
        }

        // Highlight active section on scroll
        function highlightActive() {
            const scrollPos = window.scrollY + 100;
            let activeLink = null;

            headings.forEach(function(heading) {
                if (heading.offsetTop <= scrollPos) {
                    activeLink = pagetoc.querySelector('a[href="#' + heading.id + '"]');
                }
            });

            // Remove active class from all links
            pagetoc.querySelectorAll('a').forEach(function(link) {
                link.classList.remove('active');
            });

            // Add active class to current link
            if (activeLink) {
                activeLink.classList.add('active');
            }
        }

        // Throttle scroll events
        let scrollTimeout;
        window.addEventListener('scroll', function() {
            if (scrollTimeout) {
                window.cancelAnimationFrame(scrollTimeout);
            }
            scrollTimeout = window.requestAnimationFrame(highlightActive);
        });

        // Initial highlight
        highlightActive();
    }

    ready(createPageToc);
})();
