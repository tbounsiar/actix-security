// Version selector for mdBook
(function() {
    'use strict';

    // Get current version from URL path
    function getCurrentVersion() {
        const path = window.location.pathname;
        const match = path.match(/^\/actix-security\/([^\/]+)\//);
        if (match) {
            return match[1];
        }
        // Fallback: check if we're in a versioned directory
        const pathParts = path.split('/').filter(p => p);
        if (pathParts.length > 0) {
            const version = pathParts[0];
            if (version === 'next' || /^\d+\.\d+$/.test(version)) {
                return version;
            }
        }
        return 'next';
    }

    // Create version selector dropdown
    function createVersionSelector(versions) {
        const currentVersion = getCurrentVersion();

        const container = document.createElement('div');
        container.className = 'version-selector';
        container.style.cssText = 'margin-left: 1rem; display: flex; align-items: center;';

        const label = document.createElement('span');
        label.textContent = 'Version: ';
        label.style.cssText = 'margin-right: 0.5rem; font-size: 0.9rem;';

        const select = document.createElement('select');
        select.style.cssText = 'padding: 0.25rem 0.5rem; border-radius: 4px; border: 1px solid var(--searchbar-border-color); background: var(--searchbar-bg); color: var(--searchbar-fg); font-size: 0.9rem; cursor: pointer;';

        versions.forEach(function(version) {
            const option = document.createElement('option');
            option.value = version;
            option.textContent = version === 'next' ? 'next (dev)' : 'v' + version;
            if (version === currentVersion) {
                option.selected = true;
            }
            select.appendChild(option);
        });

        select.addEventListener('change', function() {
            const newVersion = this.value;
            const currentPath = window.location.pathname;
            // Replace the version in the current path
            const newPath = currentPath.replace(/\/[^\/]+\//, '/' + newVersion + '/');
            window.location.href = newPath;
        });

        container.appendChild(label);
        container.appendChild(select);

        return container;
    }

    // Insert version selector into the navbar
    function insertVersionSelector(versions) {
        // Wait for the menu bar to be available
        const menuBar = document.querySelector('.menu-bar') || document.querySelector('.right-buttons');
        if (menuBar) {
            const selector = createVersionSelector(versions);
            // Insert before the right buttons
            const rightButtons = menuBar.querySelector('.right-buttons');
            if (rightButtons) {
                rightButtons.insertBefore(selector, rightButtons.firstChild);
            } else {
                menuBar.appendChild(selector);
            }
        }
    }

    // Fetch versions and initialize
    function init() {
        // Try to fetch versions.json from the root
        const basePath = window.location.pathname.split('/').slice(0, 2).join('/');
        fetch(basePath + '/versions.json')
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('versions.json not found');
                }
                return response.json();
            })
            .then(function(versions) {
                if (versions && versions.length > 0) {
                    insertVersionSelector(versions);
                }
            })
            .catch(function(error) {
                console.log('Version selector not available:', error.message);
            });
    }

    // Run when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
