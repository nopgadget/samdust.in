// Blog system for dynamic markdown rendering
class BlogSystem {
    constructor() {
        this.blogPosts = [];
        this.currentPost = null;
        this.lastSearchTime = 0;
        this.searchCooldown = 500; // 500ms cooldown between searches
    }

    // Initialize the blog system
    async init() {
        await this.loadBlogPosts();
        this.setupEventListeners();
        this.renderBlogList();
    }

    // Load all blog posts from the blog folder
    async loadBlogPosts() {
        try {
            // In a real implementation, you'd fetch this from a server
            // For now, we'll use the sample posts we created
            this.blogPosts = [
                {
                    id: 'vibepwning-bdsec-ctf-2025',
                    title: 'VibePwning - BDSEC CTF 2025',
                    date: 'June 20, 2025',
                    category: 'CTF',
                    excerpt: 'Walkthrough demonstrating AI-assisted buffer overflow exploitation using Claude with Ghidra MCP server. Shows how AI integration can dramatically accelerate reverse engineering and exploit development...',
                    filename: 'VibePwning - BDSEC CTF 2025.md'
                },
                {
                    id: 'paloalto-firewall-hardening',
                    title: 'Palo Alto Firewall Hardening',
                    date: 'February 1, 2025',
                    category: 'Blue Team',
                    excerpt: 'Comprehensive guide to hardening Palo Alto firewalls including PanOS updates, configuration management, service hardening, syslog forwarding to Splunk, and security best practices...',
                    filename: 'PaloAlto Firewall Hardening.md'
                },
                {
                    id: 'windows-hardening',
                    title: 'Windows Hardening',
                    date: 'January 31, 2025',
                    category: 'Blue Team',
                    excerpt: 'Comprehensive Windows hardening guide covering tooling distribution, manual enumeration techniques, PowerShell security configurations, firewall management, and automated hardening scripts...',
                    filename: 'Windows Hardening.md'
                },
                {
                    id: 'thm-reset',
                    title: 'THM Reset',
                    date: 'January 1, 2025',
                    category: 'Writeup',
                    excerpt: 'TryHackMe room walkthrough covering domain enumeration, SMB exploitation, and privilege escalation through password resets and Kerberos attacks...',
                    filename: 'THM Reset.md'
                },
                {
                    id: 'exploiting-active-directory',
                    title: 'Exploiting Active Directory',
                    date: 'December 31, 2024',
                    category: 'Active Directory',
                    excerpt: 'Advanced Active Directory exploitation techniques including permission delegation, Kerberos delegation attacks, and automated relay methods for privilege escalation...',
                    filename: 'Exploiting Active Directory.md'
                },
                {
                    id: 'lateral-movement',
                    title: 'Lateral Movement',
                    date: 'December 29, 2024',
                    category: 'Red Team',
                    excerpt: 'Comprehensive guide to lateral movement techniques including PSExec, WinRM, WMI, scheduled tasks, and alternate authentication methods for network pivoting...',
                    filename: 'Lateral Movement.md'
                },
                {
                    id: 'enumerating-active-directory',
                    title: 'Enumerating Active Directory',
                    date: 'December 27, 2024',
                    category: 'Active Directory',
                    excerpt: 'Techniques and tools for enumerating Active Directory environments, including MMC snap-ins, PowerShell cmdlets, and SharpHound for comprehensive AD reconnaissance...',
                    filename: 'Enumerating Active Directory.md'
                },
                {
                    id: 'cracking-veracrypt-volumes',
                    title: 'Cracking VeraCrypt Volumes with Hashcat',
                    date: 'July 19, 2023',
                    category: 'Cryptography',
                    excerpt: 'Comprehensive guide to cracking VeraCrypt volumes using Hashcat, covering volume header extraction, attack modes, performance optimization, and ethical considerations...',
                    filename: 'Cracking VeraCrypt Volumes with Hashcat.md'
                }
            ];
        } catch (error) {
            console.error('Error loading blog posts:', error);
        }
    }

    // Setup event listeners
    setupEventListeners() {
        // Handle blog post clicks
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('post-link')) {
                e.preventDefault();
                const postId = e.target.getAttribute('data-post-id');
                this.loadBlogPost(postId);
            }
        });

        // Handle back button
        const backButton = document.querySelector('.back-nav-link');
        if (backButton) {
            backButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.showBlogList();
            });
        }

        // Handle search functionality
        const searchInput = document.getElementById('searchInput');
        const searchButton = document.getElementById('searchButton');
        
        if (searchInput) {
            // Search on input change (debounced)
            let searchTimeout;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.performSearch(e.target.value);
                }, 300);
            });

            // Search on Enter key
            searchInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.performSearch(e.target.value);
                }
            });
        }

        if (searchButton) {
            searchButton.addEventListener('click', () => {
                const searchValue = searchInput ? searchInput.value : '';
                this.performSearch(searchValue);
            });
        }
    }

    // Render the blog list
    renderBlogList() {
        const blogPostsContainer = document.querySelector('.blog-posts');
        if (!blogPostsContainer) return;

        blogPostsContainer.innerHTML = this.blogPosts.map(post => `
            <article class="blog-post">
                <h2 class="post-title">
                    <a href="#" class="post-link" data-post-id="${post.id}">${post.title}</a>
                </h2>
                <div class="post-meta">
                    <span class="post-date">${post.date}</span>
                    <span class="post-category">${post.category}</span>
                </div>
                <p class="post-excerpt">
                    ${post.excerpt}
                </p>
            </article>
        `).join('');
    }

    // Load and render a specific blog post
    async loadBlogPost(postId) {
        const post = this.blogPosts.find(p => p.id === postId);
        if (!post) {
            console.error('Post not found:', postId);
            return;
        }

        try {
            // Fetch the markdown content
            const response = await fetch(`blog/${post.filename}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const markdown = await response.text();
            
            // Convert markdown to HTML
            const html = this.markdownToHtml(markdown);
            
            // Update the page content
            this.renderBlogPost(post, html);
            
            // Update URL without page reload
            window.history.pushState({ postId }, post.title, `?post=${postId}`);
            
        } catch (error) {
            console.error('Error loading blog post:', error);
            // Fallback to a simple error message
            this.renderBlogPost(post, `
                <div class="error-message">
                    <h3>Error Loading Post</h3>
                    <p>Sorry, there was an error loading this blog post. Please try again later.</p>
                </div>
            `);
        }
    }

    // Convert markdown to HTML using marked.js
    markdownToHtml(markdown) {
        // Configure marked.js options with syntax highlighting
        marked.setOptions({
            breaks: true, // Convert line breaks to <br>
            gfm: true,    // GitHub Flavored Markdown
            headerIds: true, // Add IDs to headers for linking
            mangle: false,   // Don't escape HTML
            sanitize: false,  // Allow HTML in markdown
            highlight: function(code, lang) {
                if (lang && Prism.languages[lang]) {
                    try {
                        return Prism.highlight(code, Prism.languages[lang], lang);
                    } catch (err) {
                        console.warn('Prism highlighting failed for language:', lang, err);
                    }
                }
                return code;
            }
        });

        // Parse markdown to HTML
        const html = marked.parse(markdown);
        
        // Apply syntax highlighting to any code blocks that weren't processed
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = html;
        const codeBlocks = tempDiv.querySelectorAll('pre code');
        codeBlocks.forEach(block => {
            if (!block.classList.contains('language-')) {
                Prism.highlightElement(block);
            }
        });
        
        return tempDiv.innerHTML;
    }

    // Render a blog post
    renderBlogPost(post, content) {
        const blogContent = document.querySelector('.blog-content');
        if (!blogContent) return;

        blogContent.innerHTML = `
            <article class="blog-post-full">
                <header class="post-header">
                    <h1 class="post-title-full">${post.title}</h1>
                    <div class="post-meta-full">
                        <span class="post-date">${post.date}</span>
                        <span class="post-category">${post.category}</span>
                    </div>
                </header>
                <div class="post-content">
                    ${content}
                </div>
            </article>
        `;

        // Show back button and update home button
        const backLink = document.querySelector('.back-link');
        const homeLink = document.querySelector('.home-link');
        if (backLink) {
            backLink.style.display = 'block';
        }
        if (homeLink) {
            homeLink.style.display = 'block';
        }
    }

    // Show the blog list
    showBlogList() {
        const blogContent = document.querySelector('.blog-content');
        if (!blogContent) return;

        blogContent.innerHTML = `
            <h1 class="blog-title">Blog</h1>
            <p class="blog-subtitle">Infodumps, writeups, and random interesting hacks</p>
            <div class="blog-posts">
                ${this.blogPosts.map(post => `
                    <article class="blog-post">
                        <h2 class="post-title">
                            <a href="#" class="post-link" data-post-id="${post.id}">${post.title}</a>
                        </h2>
                        <div class="post-meta">
                            <span class="post-date">${post.date}</span>
                            <span class="post-category">${post.category}</span>
                        </div>
                        <p class="post-excerpt">
                            ${post.excerpt}
                        </p>
                    </article>
                `).join('')}
            </div>
        `;

        // Hide back button, show home button
        const backLink = document.querySelector('.back-link');
        const homeLink = document.querySelector('.home-link');
        if (backLink) {
            backLink.style.display = 'none';
        }
        if (homeLink) {
            homeLink.style.display = 'block';
        }

        // Update URL
        window.history.pushState({}, 'Blog', 'blog.html');
    }

    // Handle browser back/forward buttons
    handlePopState(event) {
        if (event.state && event.state.postId) {
            this.loadBlogPost(event.state.postId);
        } else {
            this.showBlogList();
        }
    }

    // Perform search through blog posts
    async performSearch(query) {
        // Rate limiting
        const now = Date.now();
        if (now - this.lastSearchTime < this.searchCooldown) {
            return; // Skip search if too soon
        }
        this.lastSearchTime = now;

        // Input validation and sanitization
        if (!query || typeof query !== 'string') {
            this.renderBlogList();
            this.updateSearchResultsInfo('');
            return;
        }

        // Sanitize and limit query length
        const sanitizedQuery = query.trim().substring(0, 100); // Limit to 100 characters
        
        if (!sanitizedQuery) {
            this.renderBlogList();
            this.updateSearchResultsInfo('');
            return;
        }

        const searchResults = [];
        const searchTerm = sanitizedQuery.toLowerCase();

        // Search through all blog posts
        for (const post of this.blogPosts) {
            let matchScore = 0;
            let matchedContent = [];

            // Search in title
            if (post.title.toLowerCase().includes(searchTerm)) {
                matchScore += 10;
                matchedContent.push('title');
            }

            // Search in excerpt
            if (post.excerpt.toLowerCase().includes(searchTerm)) {
                matchScore += 5;
                matchedContent.push('excerpt');
            }

            // Search in category
            if (post.category.toLowerCase().includes(searchTerm)) {
                matchScore += 3;
                matchedContent.push('category');
            }

            // Search in content (if available)
            try {
                const response = await fetch(`blog/${post.filename}`);
                if (response.ok) {
                    const content = await response.text();
                    if (content.toLowerCase().includes(searchTerm)) {
                        matchScore += 2;
                        matchedContent.push('content');
                    }
                }
            } catch (error) {
                console.warn('Could not search content for:', post.title);
            }

            if (matchScore > 0) {
                searchResults.push({
                    ...post,
                    matchScore,
                    matchedContent,
                    highlightedTitle: this.highlightSearchTerm(post.title, searchTerm),
                    highlightedExcerpt: this.highlightSearchTerm(post.excerpt, searchTerm)
                });
            }
        }

        // Sort by match score (highest first)
        searchResults.sort((a, b) => b.matchScore - a.matchScore);

        this.renderSearchResults(searchResults, sanitizedQuery);
        this.updateSearchResultsInfo(searchResults.length, sanitizedQuery);
    }

    // Highlight search terms in text
    highlightSearchTerm(text, searchTerm) {
        // Escape special RegExp characters to prevent RegExp injection
        const escapedSearchTerm = searchTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(${escapedSearchTerm})`, 'gi');
        return text.replace(regex, '<span class="search-highlight">$1</span>');
    }

    // Render search results
    renderSearchResults(results, query) {
        const blogPostsContainer = document.querySelector('.blog-posts');
        if (!blogPostsContainer) return;

        if (results.length === 0) {
            blogPostsContainer.innerHTML = `
                <div class="no-results">
                    <p>No blog posts found matching "${this.escapeHtml(query)}"</p>
                    <p>Try different keywords or check your spelling.</p>
                </div>
            `;
            return;
        }

        blogPostsContainer.innerHTML = results.map(post => `
            <article class="blog-post">
                <h2 class="post-title">
                    <a href="#" class="post-link" data-post-id="${this.escapeHtml(post.id)}">${post.highlightedTitle}</a>
                </h2>
                <div class="post-meta">
                    <span class="post-date">${this.escapeHtml(post.date)}</span>
                    <span class="post-category">${this.escapeHtml(post.category)}</span>
                </div>
                <p class="post-excerpt">
                    ${post.highlightedExcerpt}
                </p>
                <div class="search-match-info">
                    <small>Matched in: ${this.escapeHtml(post.matchedContent.join(', '))}</small>
                </div>
            </article>
        `).join('');
    }

    // Update search results info
    updateSearchResultsInfo(resultCount, query = '') {
        const searchResultsInfo = document.getElementById('searchResultsInfo');
        if (!searchResultsInfo) return;

        if (!query) {
            searchResultsInfo.innerHTML = '';
            return;
        }

        if (resultCount === 0) {
            searchResultsInfo.innerHTML = `No results found for "${this.escapeHtml(query)}"`;
        } else if (resultCount === 1) {
            searchResultsInfo.innerHTML = `1 result found for "${this.escapeHtml(query)}"`;
        } else {
            searchResultsInfo.innerHTML = `${resultCount} results found for "${this.escapeHtml(query)}"`;
        }
    }

    // Escape HTML to prevent XSS
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the blog system when the page loads
document.addEventListener('DOMContentLoaded', () => {
    const blogSystem = new BlogSystem();
    blogSystem.init();

    // Handle browser back/forward buttons
    window.addEventListener('popstate', (event) => {
        blogSystem.handlePopState(event);
    });

    // Check if we're loading a specific post from URL
    const urlParams = new URLSearchParams(window.location.search);
    const postId = urlParams.get('post');
    if (postId) {
        blogSystem.loadBlogPost(postId);
    }
}); 