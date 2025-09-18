// Updated Matrix Command Generator - Main Application File
// Now includes 1008+ commands across 17 categories

class CyberCommandMatrix {
    constructor() {
        this.currentTool = 'all';
        this.currentCategory = 'all';
        this.searchTerm = '';
        this.currentPage = 1;
        this.commandsPerPage = 20;
        this.globalInputs = {
            ip: '',
            username: '',
            password: '',
            domain: ''
        };

        // Enhanced tool databases - NOW WITH 1008+ COMMANDS!
        this.toolDatabases = {
            // Original databases
            netexec: NETEXEC_COMMANDS || {},
            nmap: NMAP_COMMANDS || {},
            web: WEB_COMMANDS || {},
            recon: RECON_COMMANDS || {},
            exploitation: EXPLOITATION_COMMANDS || {},
            password: PASSWORD_COMMANDS || {},
            windows: WINDOWS_COMMANDS || {},
            linux: LINUX_COMMANDS || {},
            mobile: MOBILE_COMMANDS || {},
            cloud: CLOUD_COMMANDS || {},
            forensics: FORENSICS_COMMANDS || {},
            exploit_notes: EXPLOIT_NOTES || {},
            
            // NEW COMPREHENSIVE DATABASES
            active_directory: ACTIVE_DIRECTORY_COMMANDS || {},
            privilege_escalation: PRIVILEGE_ESCALATION_COMMANDS || {},
            post_exploitation: POST_EXPLOITATION_COMMANDS || {},
            osint: OSINT_COMMANDS || {},
            pivoting: PIVOTING_COMMANDS || {},
            wireless: WIRELESS_COMMANDS || {},
            database: DATABASE_COMMANDS || {},
            advanced_pentesting: ADVANCED_PENTESTING_COMMANDS || {}
        };

        this.init();
    }

    init() {
        console.log('🚀 Matrix Command Generator initializing...');
        console.log('📊 Loading 1008+ penetration testing commands...');
        this.setupEventListeners();
        this.updateGlobalInputs();
        this.loadSavedState();
        this.switchTool('all');
        this.showWelcomeToast();
        console.log('✅ Matrix ready with comprehensive command database!');
    }

    setupEventListeners() {
        // Global input listeners for real-time updates
        ['ip', 'username', 'password', 'domain'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('input', (e) => {
                    console.log(`📝 ${id}: ${e.target.value}`);
                    this.updateGlobalInputs();
                    this.currentPage = 1;
                    this.renderCommands();
                    this.saveState();
                });
                element.addEventListener('paste', () => {
                    setTimeout(() => {
                        this.updateGlobalInputs();
                        this.renderCommands();
                    }, 10);
                });
            }
        });

        // Tool selection
        document.querySelectorAll('.tool-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tool = btn.dataset.tool;
                this.switchTool(tool);
            });
        });

        // Search functionality
        const searchInput = document.getElementById('searchCommands');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchTerm = e.target.value.toLowerCase();
                this.currentPage = 1;
                this.renderCommands();
            });
        }

        // Header buttons
        document.getElementById('helpBtn')?.addEventListener('click', () => {
            this.showModal('helpModal');
        });
        document.getElementById('exportBtn')?.addEventListener('click', () => {
            this.exportCommands();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.key === 'k') {
                e.preventDefault();
                document.getElementById('searchCommands')?.focus();
            }
            if (e.key === 'Escape') {
                this.closeAllModals();
            }
        });
    }

    updateGlobalInputs() {
        this.globalInputs = {
            ip: document.getElementById('ip')?.value.trim() || '',
            username: document.getElementById('username')?.value.trim() || '',
            password: document.getElementById('password')?.value.trim() || '',
            domain: document.getElementById('domain')?.value.trim() || ''
        };
    }

    switchTool(toolName) {
        console.log(`🔄 Switching to: ${toolName}`);
        this.currentTool = toolName;
        this.currentCategory = 'all';
        this.currentPage = 1;

        // Update active tool button
        document.querySelectorAll('.tool-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tool === toolName);
        });

        this.renderCategoryFilter();
        this.renderCommands();
    }

    renderCategoryFilter() {
        const categoryFilter = document.getElementById('categoryFilter');
        if (!categoryFilter) return;

        const categories = this.getAvailableCategories();
        if (categories.length === 0) {
            categoryFilter.style.display = 'none';
            return;
        }

        categoryFilter.style.display = 'flex';
        categoryFilter.innerHTML = `
            <button class="category-btn active" data-category="all">All Categories</button>
            ${categories.map(category => `
                <button class="category-btn" data-category="${category}">${category}</button>
            `).join('')}
        `;

        // Add category listeners
        categoryFilter.querySelectorAll('.category-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.currentCategory = btn.dataset.category;
                this.currentPage = 1;
                categoryFilter.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.renderCommands();
            });
        });
    }

    getAvailableCategories() {
        const categories = new Set();
        const commands = this.getCurrentCommands();
        Object.values(commands).flat().forEach(cmd => {
            if (cmd.category) categories.add(cmd.category);
        });
        return Array.from(categories).sort();
    }

    getCurrentCommands() {
        if (this.currentTool === 'all') {
            const allCommands = {};
            Object.entries(this.toolDatabases).forEach(([toolName, toolCommands]) => {
                if (toolCommands && typeof toolCommands === 'object') {
                    Object.entries(toolCommands).forEach(([category, commands]) => {
                        if (Array.isArray(commands)) {
                            const key = `${toolName}_${category}`;
                            allCommands[key] = commands;
                        }
                    });
                }
            });
            return allCommands;
        } else {
            return this.toolDatabases[this.currentTool] || {};
        }
    }

    getAllFilteredCommands() {
        const commands = this.getCurrentCommands();
        let allCommands = [];

        Object.values(commands).forEach(commandArray => {
            if (Array.isArray(commandArray)) {
                allCommands = allCommands.concat(commandArray);
            }
        });

        // Filter by category
        if (this.currentCategory !== 'all') {
            allCommands = allCommands.filter(cmd => cmd.category === this.currentCategory);
        }

        // Filter by search term
        if (this.searchTerm) {
            allCommands = allCommands.filter(cmd => 
                cmd.name.toLowerCase().includes(this.searchTerm) ||
                cmd.description.toLowerCase().includes(this.searchTerm) ||
                cmd.command.toLowerCase().includes(this.searchTerm) ||
                cmd.category.toLowerCase().includes(this.searchTerm)
            );
        }

        return allCommands;
    }

    processCommand(command) {
        const inputs = this.globalInputs;
        return command
            .replace(/{ip}/g, inputs.ip || '{ip}')
            .replace(/{username}/g, inputs.username || '{username}')
            .replace(/{password}/g, inputs.password || '{password}')
            .replace(/{domain}/g, inputs.domain || '{domain}')
            .replace(/{bssid}/g, inputs.bssid || '{bssid}')
            .replace(/{interface}/g, inputs.interface || '{interface}')
            .replace(/{port}/g, inputs.port || '{port}')
            .replace(/{url}/g, inputs.url || '{url}')
            .replace(/{file}/g, inputs.file || '{file}')
            .replace(/{hash}/g, inputs.hash || '{hash}');
    }

    getCategoryClass(category) {
        const categoryMap = {
            'Nmap': 'nmap',
            'Web Application': 'web',
            'NetExec': 'netexec',
            'SMB': 'netexec',
            'LDAP': 'netexec',
            'Exploitation': 'exploitation',
            'Buffer Overflow': 'exploitation',
            'Windows PrivEsc': 'windows',
            'Linux PrivEsc': 'linux',
            'Active Directory': 'active-directory',
            'OSINT': 'osint',
            'Wireless': 'wireless',
            'Cloud Security': 'cloud',
            'Container Security': 'cloud',
            'Database': 'database',
            'Forensics': 'forensics'
        };
        return categoryMap[category] || 'default';
    }

    renderCommands() {
        const commandsGrid = document.getElementById('commandsGrid');
        const emptyState = document.getElementById('emptyState');
        if (!commandsGrid) return;

        const allCommands = this.getAllFilteredCommands();
        const totalCommands = allCommands.length;
        const totalPages = Math.ceil(totalCommands / this.commandsPerPage);

        console.log(`📊 Rendering ${totalCommands} commands (page ${this.currentPage}/${totalPages})`);

        // Get commands for current page
        const startIndex = (this.currentPage - 1) * this.commandsPerPage;
        const endIndex = startIndex + this.commandsPerPage;
        const paginatedCommands = allCommands.slice(startIndex, endIndex);

        if (paginatedCommands.length === 0) {
            commandsGrid.style.display = 'none';
            if (emptyState) emptyState.style.display = 'block';
            this.renderPagination(0, 0);
            return;
        }

        commandsGrid.style.display = 'grid';
        if (emptyState) emptyState.style.display = 'none';

        commandsGrid.innerHTML = paginatedCommands.map((cmd, index) => {
            const processedCommand = this.processCommand(cmd.command);
            const categoryClass = this.getCategoryClass(cmd.category);
            return `
                <div class="command-card" onclick="matrix.copyCommand('${processedCommand.replace(/'/g, "\\'")}', ${cmd.id})">
                    <div class="command-id">#${cmd.id}</div>
                    <div class="command-header">
                        <h3 class="command-title">${cmd.name}</h3>
                        <span class="command-category ${categoryClass}">${cmd.category}</span>
                    </div>
                    <p class="command-description">${cmd.description}</p>
                    <div class="command-code">${processedCommand}</div>
                    <div class="command-actions">
                        <button class="copy-btn" onclick="event.stopPropagation(); matrix.copyCommand('${processedCommand.replace(/'/g, "\\'")}', ${cmd.id})">
                            <i class="fas fa-copy"></i>
                            Copy Command
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        this.renderPagination(totalPages, totalCommands);
    }

    renderPagination(totalPages, totalCommands) {
        const paginationContainer = document.getElementById('pagination');
        if (!paginationContainer) return;

        if (totalPages <= 1) {
            paginationContainer.style.display = 'none';
            return;
        }

        paginationContainer.style.display = 'flex';

        const maxVisiblePages = 7;
        const startPage = Math.max(1, this.currentPage - Math.floor(maxVisiblePages / 2));
        const endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);

        let paginationHTML = `
            <button class="pagination-btn" onclick="matrix.goToPage(1)" ${this.currentPage === 1 ? 'disabled' : ''}>
                <i class="fas fa-angle-double-left"></i>
            </button>
            <button class="pagination-btn" onclick="matrix.goToPage(${this.currentPage - 1})" ${this.currentPage === 1 ? 'disabled' : ''}>
                <i class="fas fa-angle-left"></i>
            </button>
        `;

        for (let i = startPage; i <= endPage; i++) {
            paginationHTML += `
                <button class="pagination-btn ${i === this.currentPage ? 'active' : ''}" onclick="matrix.goToPage(${i})">
                    ${i}
                </button>
            `;
        }

        paginationHTML += `
            <button class="pagination-btn" onclick="matrix.goToPage(${this.currentPage + 1})" ${this.currentPage === totalPages ? 'disabled' : ''}>
                <i class="fas fa-angle-right"></i>
            </button>
            <button class="pagination-btn" onclick="matrix.goToPage(${totalPages})" ${this.currentPage === totalPages ? 'disabled' : ''}>
                <i class="fas fa-angle-double-right"></i>
            </button>
        `;

        paginationContainer.innerHTML = paginationHTML;
    }

    goToPage(page) {
        this.currentPage = page;
        this.renderCommands();
        window.scrollTo(0, 0);
    }

    copyCommand(command, id) {
        navigator.clipboard.writeText(command).then(() => {
            this.showToast(`Command #${id} copied to clipboard!`, 'success');
        }).catch(err => {
            console.error('Failed to copy command:', err);
            this.showToast('Failed to copy command', 'error');
        });
    }

    showToast(message, type = 'success') {
        const existingToast = document.querySelector('.toast');
        if (existingToast) {
            existingToast.remove();
        }

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <div class="toast-content">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}"></i>
                <span>${message}</span>
            </div>
            <button class="toast-close" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;

        document.body.appendChild(toast);

        // Show toast
        setTimeout(() => toast.classList.add('show'), 100);

        // Auto-hide after 3 seconds
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.remove('show');
                setTimeout(() => toast.remove(), 300);
            }
        }, 3000);
    }

    exportCommands() {
        const commands = this.getAllFilteredCommands();
        const content = commands.map(cmd => {
            const processedCommand = this.processCommand(cmd.command);
            return `# ${cmd.name}\n# Category: ${cmd.category}\n# Description: ${cmd.description}\n${processedCommand}\n`;
        }).join('\n');

        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `matrix-commands-${new Date().toISOString().split('T')[0]}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showToast(`Exported ${commands.length} commands!`, 'success');
    }

    showWelcomeToast() {
        setTimeout(() => {
            this.showToast('🎉 Matrix loaded with 1008+ penetration testing commands!', 'success');
        }, 1000);
    }

    showModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
        }
    }

    closeAllModals() {
        document.querySelectorAll('.modal').forEach(modal => {
            modal.classList.remove('show');
        });
    }

    saveState() {
        try {
            localStorage.setItem('matrixState', JSON.stringify({
                currentTool: this.currentTool,
                currentCategory: this.currentCategory,
                searchTerm: this.searchTerm,
                globalInputs: this.globalInputs
            }));
        } catch (e) {
            console.warn('Could not save state:', e);
        }
    }

    loadSavedState() {
        try {
            const saved = localStorage.getItem('matrixState');
            if (saved) {
                const state = JSON.parse(saved);
                this.currentTool = state.currentTool || 'all';
                this.currentCategory = state.currentCategory || 'all';
                this.searchTerm = state.searchTerm || '';
                this.globalInputs = { ...this.globalInputs, ...(state.globalInputs || {}) };

                // Restore form values
                Object.entries(this.globalInputs).forEach(([key, value]) => {
                    const input = document.getElementById(key);
                    if (input) input.value = value;
                });

                const searchInput = document.getElementById('searchCommands');
                if (searchInput) searchInput.value = this.searchTerm;
            }
        } catch (e) {
            console.warn('Could not load saved state:', e);
        }
    }
}

// Initialize the Matrix when DOM is loaded
let matrix;
document.addEventListener('DOMContentLoaded', () => {
    matrix = new CyberCommandMatrix();
});

// Make matrix globally available
window.matrix = matrix;