// Blog system for dynamic markdown rendering
class BlogSystem {
    constructor() {
        this.blogPosts = [];
        this.currentPost = null;
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

    // Convert markdown to HTML (simplified version)
    markdownToHtml(markdown) {
        let html = markdown;

        // Convert headers
        html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
        html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
        html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

        // Convert bold and italic
        html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

        // Convert code blocks
        html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>');
        html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

        // Convert lists
        html = html.replace(/^\s*[-*]\s+(.*$)/gim, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>)/s, '<ul>$1</ul>');

        // Convert numbered lists
        html = html.replace(/^\s*\d+\.\s+(.*$)/gim, '<li>$1</li>');
        html = html.replace(/(<li>.*<\/li>)/s, '<ol>$1</ol>');

        // Convert paragraphs
        html = html.replace(/\n\n/g, '</p><p>');
        html = '<p>' + html + '</p>';

        // Clean up empty paragraphs
        html = html.replace(/<p><\/p>/g, '');
        html = html.replace(/<p>(<h[1-6]>.*<\/h[1-6]>)<\/p>/g, '$1');
        html = html.replace(/<p>(<ul>.*<\/ul>)<\/p>/g, '$1');
        html = html.replace(/<p>(<ol>.*<\/ol>)<\/p>/g, '$1');
        html = html.replace(/<p>(<pre>.*<\/pre>)<\/p>/g, '$1');

        return html;
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