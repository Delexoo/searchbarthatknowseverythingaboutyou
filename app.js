        const API_BASE = (location.protocol === 'file:') ? 'http://localhost:8080' : '';
        const APP_CONFIG = window.APP_CONFIG || {};
        const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
        const OPENROUTER_MODELS = [
            APP_CONFIG.OPENROUTER_MODEL,
            'openai/gpt-4o-mini',
            'google/gemini-2.0-flash-001',
            'meta-llama/llama-3.3-70b-instruct'
        ].filter(Boolean);
        const AI_SYSTEM_PROMPT = 'You are a research assistant for open-source intelligence (OSINT) using only public information and public lookup tools. Help the user understand phone numbers, emails, usernames, IPs, and domains, and point them to legitimate public sources. Be concise and structured. Do not provide instructions for unauthorized access or attacks.';

        function detectLookupType(inputText) {
            const value = String(inputText || '').trim();
            const compact = value.replace(/[\s().-]/g, '');
            if (/^[\+]?\d{7,15}$/.test(compact)) return 'phone';
            if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'email';
            if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
            if (/\./.test(value) && (value.toLowerCase().includes('http') || value.toLowerCase().includes('www') || value.split('.').length >= 2)) return 'domain';
            if (/^[a-zA-Z0-9_]{3,20}$/.test(value)) return 'username';
            return 'general';
        }

        async function enrichQuery(message) {
            const value = String(message || '').trim();
            const type = detectLookupType(value);
            const parts = [];
            try {
                if (type === 'ip') {
                    const response = await fetch('https://ipwho.is/' + encodeURIComponent(value));
                    if (response.ok) parts.push('IP geolocation: ' + JSON.stringify(await response.json()));
                } else if (type === 'domain') {
                    const host = value.replace(/^https?:\/\//i, '').split('/')[0];
                    const response = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=A');
                    if (response.ok) parts.push('DNS A: ' + JSON.stringify(await response.json()));
                } else if (type === 'username') {
                    const response = await fetch('https://api.github.com/users/' + encodeURIComponent(value));
                    if (response.ok) parts.push('GitHub profile: ' + JSON.stringify(await response.json()));
                    else if (response.status === 404) parts.push('GitHub: no user named ' + value);
                } else if (type === 'email') {
                    const domain = value.split('@')[1];
                    if (domain) {
                        const response = await fetch('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=MX');
                        if (response.ok) parts.push('Email domain MX: ' + JSON.stringify(await response.json()));
                    }
                }
            } catch (error) {
                console.warn('Lookup enrichment skipped', error);
            }
            return parts.join('\n');
        }

        async function callOpenRouter(messages, signal) {
            const apiKey = APP_CONFIG.OPENROUTER_API_KEY;
            if (!apiKey) throw new Error('OpenRouter key missing from config.js');
            let lastError = null;
            for (const model of OPENROUTER_MODELS) {
                const response = await fetch(OPENROUTER_URL, {
                    method: 'POST',
                    headers: {
                        Authorization: 'Bearer ' + apiKey,
                        'Content-Type': 'application/json',
                        'HTTP-Referer': location.origin,
                        'X-OpenRouter-Title': 'searchbarthatknowseverythingaboutyou'
                    },
                    body: JSON.stringify({ model, messages, temperature: 0.7 }),
                    signal
                });
                const data = await response.json();
                if (!response.ok) {
                    lastError = new Error(data.error?.message || 'OpenRouter HTTP ' + response.status);
                    continue;
                }
                const text = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
                if (text) return text;
                lastError = new Error('Empty model response');
            }
            throw lastError || new Error('All OpenRouter models failed');
        }

        function getLocalOsintResources(resourceType, inputValue) {
            const cleanValue = String(inputValue || '').replace(/[\s+()-]/g, '');
            const encoded = encodeURIComponent(inputValue || '');
            const domainPart = String(inputValue || '').includes('@') ? String(inputValue).split('@')[1] : inputValue;
            const resources = {
                phone_lookup: [
                    { name: 'TrueCaller', url: 'https://www.truecaller.com/search/' + cleanValue },
                    { name: 'WhitePages', url: 'https://www.whitepages.com/phone/' + cleanValue }
                ],
                email_breach: [
                    { name: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/account/' + encoded }
                ],
                username_github: [
                    { name: 'GitHub Profile', url: 'https://github.com/' + inputValue },
                    { name: 'GitHub Search', url: 'https://github.com/search?q=' + encoded }
                ],
                domain_whois: [
                    { name: 'Whois Lookup', url: 'https://whois.net/' + inputValue },
                    { name: 'ICANN Lookup', url: 'https://lookup.icann.org/lookup' }
                ],
                ip_geo: [
                    { name: 'IPInfo', url: 'https://ipinfo.io/' + inputValue }
                ],
                general_search: [
                    { name: 'Google Search', url: 'https://www.google.com/search?q=' + encoded },
                    { name: 'DuckDuckGo', url: 'https://duckduckgo.com/?q=' + encoded }
                ]
            };
            return resources[resourceType] || resources.general_search;
        }

        async function requestChat(message, signal) {
            const context = await enrichQuery(message);
            const userContent = context
                ? ('Public lookup data:\n' + context + '\n\nUser query: ' + message)
                : message;
            const messages = [
                { role: 'system', content: AI_SYSTEM_PROMPT },
                { role: 'user', content: userContent }
            ];
            if (APP_CONFIG.OPENROUTER_API_KEY) {
                return { type: 'ai_response', response: await callOpenRouter(messages, signal) };
            }
            const response = await fetch(API_BASE + '/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: message }),
                signal
            });
            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.error || ('HTTP error! status: ' + response.status));
            }
            return response.json();
        }

        async function requestSummary(conversationText, signal) {
            const instruction = 'Summarize this entire conversation in exactly 2 brief sentences. Be concise and capture the main topics discussed.';
            if (APP_CONFIG.OPENROUTER_API_KEY) {
                const summary = await callOpenRouter([
                    { role: 'system', content: 'You summarize conversations briefly and clearly.' },
                    { role: 'user', content: instruction + '\n\nConversation:\n' + conversationText }
                ], signal);
                return { summary, response: summary };
            }
            const response = await fetch(API_BASE + '/summarize', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ conversation: conversationText, instruction })
            });
            if (!response.ok) throw new Error('Failed to summarize');
            return response.json();
        }

        const searchInput = document.getElementById('searchInput');
        const addButton = document.getElementById('addButton');
        const addOptionsDropdown = document.getElementById('addOptionsDropdown');
        const sendButtonInner = document.getElementById('sendButtonInner');
        const moreOptionsButton = document.getElementById('moreOptionsButton');
        const animationToggle = document.getElementById('animationToggle');
        const gravityToggle = document.getElementById('gravityToggle');
        const bubbleToggle = document.getElementById('bubbleToggle');
        const aiResponse = document.getElementById('aiResponse');
        const newChatButton = document.getElementById('newChatButton');
        const examplePrompts = document.getElementById('examplePrompts');
        
        // Ensure inner send button is ALWAYS visible - prevent any hiding
        function ensureInnerButtonVisible() {
            if (sendButtonInner) {
                // CRITICAL: Ensure button is inside search-input-wrapper and in correct position
                const wrapper = document.querySelector('.search-input-wrapper');
                if (wrapper) {
                    // Check if button is in the right place
                    if (!wrapper.contains(sendButtonInner)) {
                        // Move it to the correct parent (after input, before more-options-button)
                        const input = document.getElementById('searchInput');
                        const moreOptionsBtn = document.getElementById('moreOptionsButton');
                        if (input) {
                            // Insert after input but before more-options-button
                            if (moreOptionsBtn && moreOptionsBtn.parentNode === wrapper) {
                                wrapper.insertBefore(sendButtonInner, moreOptionsBtn);
                            } else {
                                wrapper.insertBefore(sendButtonInner, input.nextSibling);
                            }
                        } else {
                            wrapper.appendChild(sendButtonInner);
                        }
                    }
                }
                
                // Force all positioning and visibility properties
                sendButtonInner.style.setProperty('display', 'flex', 'important');
                sendButtonInner.style.setProperty('visibility', 'visible', 'important');
                sendButtonInner.style.setProperty('opacity', '1', 'important');
                sendButtonInner.style.setProperty('z-index', '999', 'important');
                sendButtonInner.style.setProperty('position', 'absolute', 'important');
                
                // Adjust position based on typing mode
                if (wrapper && wrapper.classList.contains('typing')) {
                    sendButtonInner.style.setProperty('right', '130px', 'important'); // Shifted right a tiny bit more in typing mode
                } else {
                    sendButtonInner.style.setProperty('right', '12px', 'important'); // Original position in initial mode
                }
                
                sendButtonInner.style.setProperty('top', '50%', 'important');
                sendButtonInner.style.setProperty('transform', 'translateY(-50%)', 'important');
                sendButtonInner.style.setProperty('margin', '0', 'important');
                sendButtonInner.style.setProperty('padding', '0', 'important');
                sendButtonInner.style.setProperty('left', 'auto', 'important');
                sendButtonInner.style.setProperty('bottom', 'auto', 'important');
            }
        }
        
        // Call on load and periodically to ensure it stays visible
        ensureInnerButtonVisible();
        setInterval(ensureInnerButtonVisible, 100); // Check every 100ms to prevent hiding
        
        // Watch for typing mode changes and update button position
        const wrapperElement = document.querySelector('.search-input-wrapper');
        if (wrapperElement && sendButtonInner) {
            const observer = new MutationObserver(() => {
                ensureInnerButtonVisible();
            });
            observer.observe(wrapperElement, {
                attributes: true,
                attributeFilter: ['class']
            });
        }
        const searchBarDivider = document.getElementById('searchBarDivider');
        
        // Conversation history
        let conversationHistory = [];
        
        // Track if prompts are currently displayed
        let promptsCurrentlyShown = false;
        
        // Function to show/hide example prompts
        function updateExamplePrompts() {
            if (!examplePrompts) return;
            
            const hasHistory = conversationHistory.length > 0;
            const inputValue = searchInput.value.trim();
            const isTyping = mainContainer.classList.contains('typing');
            
            // Show while typing (any length) when no history and search bar is in typing mode
            // Only hide when there's conversation history (message was sent)
            const shouldShow = !hasHistory && isTyping && inputValue.length > 0;
            
            if (shouldShow) {
                // Only load prompts once if they haven't been loaded yet
                // After that, they only refresh when refresh button is clicked
                if (!promptsCurrentlyShown) {
                    loadExamplePrompts();
                    promptsCurrentlyShown = true;
                }
                
                // Ensure fixed positioning in center
                examplePrompts.style.position = 'fixed';
                examplePrompts.style.top = '50%';
                examplePrompts.style.left = '50%';
                examplePrompts.style.transform = 'translate(-50%, -50%)';
                examplePrompts.classList.add('show');
            } else {
                examplePrompts.classList.remove('show');
                // Don't reset the flag - keep prompts loaded
                // They will only refresh when refresh button is clicked
            }
        }
        
        // Handle example prompt clicks
        function setupExamplePrompts() {
            const promptItems = examplePrompts.querySelectorAll('.example-prompt-item');
            promptItems.forEach(item => {
                const useButton = item.querySelector('.example-prompt-button');
                const promptText = item.getAttribute('data-prompt');
                
                // Remove any existing event listeners by cloning the button
                const newButton = useButton.cloneNode(true);
                useButton.parentNode.replaceChild(newButton, useButton);
                
                // Handle "Use" button click - paste prompt into search bar (replaces current text)
                newButton.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    if (isProcessing) return;
                    
                    // Replace the current search input value with the new prompt
                    searchInput.value = promptText;
                    
                    // Trigger input event to ensure any listeners are notified
                    searchInput.dispatchEvent(new Event('input', { bubbles: true }));
                    
                    // Focus the search input so user can modify if needed
                    searchInput.focus();
                    
                    // Move cursor to end of text (or right after colon if present)
                    let cursorPos = promptText.length;
                    const colonIndex = promptText.lastIndexOf(':');
                    if (colonIndex !== -1) {
                        // Position cursor right after the colon for easy pasting
                        cursorPos = colonIndex + 1;
                    }
                    // Use setTimeout to ensure the value is set before setting cursor position
                    setTimeout(() => {
                        searchInput.setSelectionRange(cursorPos, cursorPos);
                    }, 0);
                    
                    // Don't hide example prompts - they'll disappear when message is sent
                    logFrontend('Example prompt pasted', `"${promptText.substring(0, 50)}..."`);
                });
            });
        }
        
        // Hardcoded example prompts pool - diverse OSINT prompts with colons for easy pasting
        const examplePromptsPool = [
            // Phone Numbers
            "Help me investigate this phone number:",
            "What information can I find about this phone number:",
            "This phone number looks suspicious, help me research it:",
            "How can I verify who owns this phone number:",
            "I need to find social media accounts linked to this phone number:",
            
            // Names
            "Help me research this person's name:",
            "What information is available about this name:",
            "I want to find social media accounts for this person:",
            "How can I investigate this person's online presence:",
            "What OSINT tools can help me research this name:",
            
            // Email Addresses
            "Help me investigate this email address:",
            "What can I find about this email:",
            "How do I find social media accounts linked to this email:",
            "I need to verify information about this email address:",
            "What information is available about this email:",
            
            // Social Media Handles
            "Help me find more information from this Instagram handle:",
            "What can I discover about this Twitter/X handle:",
            "I want to research this TikTok username:",
            "How can I investigate this Facebook profile:",
            "What information is available about this social media handle:",
            "Help me find other accounts linked to this username:",
            
            // Usernames
            "What can I find about this username:",
            "Help me research this username across platforms:",
            "I need to find all accounts using this username:",
            "What information can I gather about this username:",
            "How do I investigate this username:",
            
            // Addresses
            "Help me research this address:",
            "What information can I find about this location:",
            "I want to investigate this physical address:",
            "How can I verify information about this address:",
            "What OSINT tools can help me research this address:",
            
            // Faces/Images
            "What tools can help me identify faces?",
            "How do I perform reverse image searches?",
            "What OSINT tools are available for face recognition?",
            "How can I identify a person from a photo?",
            "What are the best tools for reverse image search?",
            
            // IP Addresses
            "Help me investigate this IP address:",
            "What information can I find about this IP:",
            "How can I research this IP address:",
            "I need to find the location of this IP address:",
            "What OSINT tools can help me investigate this IP:",
            
            // Domains/Websites
            "Help me research this domain:",
            "What information can I find about this website:",
            "How can I investigate this domain name:",
            "I want to find who owns this domain:",
            "What OSINT techniques can I use for this domain:",
            
            // General Investigation
            "I want to scrape information about this person:",
            "I need to find more details about this person:",
            "What OSINT tools can I use for this investigation:",
            "How do I conduct a comprehensive OSINT investigation on:",
            "I need OSINT techniques for investigating:",
            
            // Vehicle Information
            "Help me research this license plate:",
            "What information can I find about this vehicle:",
            "How can I investigate this license plate number:",
            "I need to find the owner of this vehicle:",
            
            // Company/Business
            "Help me research this company:",
            "What information can I find about this business:",
            "How can I investigate this organization:",
            "I need to find details about this company:",
            
            // Cryptocurrency
            "Help me investigate this cryptocurrency address:",
            "What information can I find about this Bitcoin address:",
            "How can I research this crypto wallet:",
            
            // Phone Numbers (more variations)
            "I want to know more about this phone number:",
            "This phone number is bothering me, help me investigate:",
            "Help me gather information about this phone number:",
            "I need to verify who this phone number belongs to:"
        ];
        
        // Track animation timeout to prevent duplicates
        let promptAnimationTimeout = null;
        
        // Load and populate example prompts (randomized from pool)
        function loadExamplePrompts() {
            // Clear any existing animation timeout
            if (promptAnimationTimeout) {
                clearTimeout(promptAnimationTimeout);
                promptAnimationTimeout = null;
            }
            
            // Randomly select exactly 4 prompts from the pool
            const shuffled = [...examplePromptsPool].sort(() => Math.random() - 0.5);
            const selectedPrompts = shuffled.slice(0, 4);
            
            // Clear ALL existing content completely (prevents duplicates)
            examplePrompts.innerHTML = '';
            
            // Create label with refresh button (static at top)
            const labelEl = document.createElement('div');
            labelEl.className = 'example-prompts-label';
            labelEl.innerHTML = '<span>Example Prompts</span>';
            
            const refreshAllButton = document.createElement('button');
            refreshAllButton.className = 'example-prompts-refresh-all';
            refreshAllButton.title = 'Refresh all prompts';
            refreshAllButton.innerHTML = `
                <svg viewBox="0 0 24 24">
                    <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/>
                </svg>
            `;
            refreshAllButton.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                // Refresh all prompts - this is the only way to get new prompts
                loadExamplePrompts();
                // Keep the flag as true since prompts are still shown
                promptsCurrentlyShown = true;
                logFrontend('All prompts refreshed');
            });
            
            labelEl.appendChild(refreshAllButton);
            examplePrompts.appendChild(labelEl);
            
            // Create separate container for prompts list
            const promptsList = document.createElement('div');
            promptsList.className = 'example-prompts-list';
            promptsList.id = 'examplePromptsList';
            // Clear any existing prompts in the list
            promptsList.innerHTML = '';
            examplePrompts.appendChild(promptsList);
            
            // Animate exactly 4 prompts with typewriter effect
            // Double-check: ensure we only pass exactly 4 prompts
            const finalPrompts = selectedPrompts.slice(0, 4);
            animateExamplePrompts(finalPrompts);
            
            logFrontend('Example prompts loaded', `Count: ${selectedPrompts.length}`);
        }
        
        // Animate example prompts with typewriter effect
        function animateExamplePrompts(prompts) {
            // Clear any existing animation timeout
            if (promptAnimationTimeout) {
                clearTimeout(promptAnimationTimeout);
                promptAnimationTimeout = null;
            }
            
            // Ensure we only have exactly 4 prompts
            const promptsToShow = prompts.slice(0, 4);
            
            let promptIndex = 0;
            
            function animateNextPrompt() {
                if (promptIndex >= promptsToShow.length) {
                    // All prompts animated, verify we have exactly 4 and setup click handlers
                    const promptsList = document.getElementById('examplePromptsList');
                    if (promptsList) {
                        const existingItems = promptsList.querySelectorAll('.example-prompt-item');
                        // Ensure we have exactly 4 prompts (remove extras if any, add missing if any)
                        if (existingItems.length !== 4) {
                            // If we don't have exactly 4, something went wrong - reload
                            console.warn(`Expected 4 prompts but found ${existingItems.length}, reloading...`);
                            loadExamplePrompts();
                            return;
                        }
                    }
                    setupExamplePrompts();
                    return;
                }
                
                const prompt = promptsToShow[promptIndex];
                
                // Create prompt item container
                const item = document.createElement('div');
                item.className = 'example-prompt-item';
                item.setAttribute('data-prompt', prompt);
                item.style.opacity = '0';
                
                const text = document.createElement('span');
                text.className = 'example-prompt-text';
                text.textContent = '';
                
                const useButton = document.createElement('button');
                useButton.className = 'example-prompt-button';
                useButton.textContent = 'Use';
                useButton.style.opacity = '0';
                
                item.appendChild(text);
                item.appendChild(useButton);
                
                // Add to prompts list container (not main container)
                const promptsList = document.getElementById('examplePromptsList');
                if (promptsList) {
                    // Safety check: only prevent adding if we somehow have more than 4
                    // During normal animation, we add one at a time, so this should never trigger
                    const existingItems = promptsList.querySelectorAll('.example-prompt-item');
                    if (existingItems.length > 4) {
                        // Remove any extra items beyond 4 (shouldn't happen, but safety check)
                        for (let i = 4; i < existingItems.length; i++) {
                            existingItems[i].remove();
                        }
                    }
                    // Always append the item - we control the count via promptsToShow.length
                    promptsList.appendChild(item);
                } else {
                    // Fallback if list doesn't exist
                    const existingItems = examplePrompts.querySelectorAll('.example-prompt-item');
                    if (existingItems.length > 4) {
                        // Remove extras if somehow we have more than 4
                        for (let i = 4; i < existingItems.length; i++) {
                            existingItems[i].remove();
                        }
                    }
                    examplePrompts.appendChild(item);
                }
                
                // Fade in the item
                setTimeout(() => {
                    item.style.transition = 'opacity 0.3s ease';
                    item.style.opacity = '1';
                }, 50);
                
                // Typewriter effect for the text
                // Clear any existing animation for this text element
                if (text._typewriterTimeout) {
                    clearTimeout(text._typewriterTimeout);
                    text._typewriterTimeout = null;
                }
                
                let charIndex = 0;
                const typeSpeed = 30; // milliseconds per character
                
                function typeNextChar() {
                    if (charIndex < prompt.length) {
                        // Use substring to prevent character mixing
                        text.textContent = prompt.substring(0, charIndex + 1);
                        charIndex++;
                        text._typewriterTimeout = setTimeout(typeNextChar, typeSpeed);
                    } else {
                        // Clear timeout reference when done
                        text._typewriterTimeout = null;
                        // Text complete, show buttons
                        setTimeout(() => {
                            useButton.style.transition = 'opacity 0.3s ease';
                            useButton.style.opacity = '1';
                            // Move to next prompt after a short delay
                            setTimeout(() => {
                                promptIndex++;
                                animateNextPrompt();
                            }, 200);
                        }, 100);
                    }
                }
                
                // Start typing after a short delay
                setTimeout(() => {
                    typeNextChar();
                }, 100);
            }
            
            // Start animating first prompt
            animateNextPrompt();
        }
        
        // Don't load prompts on page load - they'll load when user starts typing
        // Prompts only refresh when refresh button is clicked
        
        // Frontend logging function
        function logFrontend(action, details = '') {
            try {
                fetch(API_BASE + '/log', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action, details: details })
                }).catch(() => {}); // Silently fail if server not available
            } catch (e) {}
        }
        
        // Function to parse markdown and convert to HTML
        function parseMarkdown(text) {
            let html = text;
            
            // Horizontal rules: --- or ***
            html = html.replace(/^(\s*[-*]{3,})\s*$/gm, '<hr>');
            
            // Headers: ###, ##, #
            html = html.replace(/^###\s+(.+)$/gm, '<h3>$1</h3>');
            html = html.replace(/^##\s+(.+)$/gm, '<h2>$1</h2>');
            html = html.replace(/^#\s+(.+)$/gm, '<h1>$1</h1>');
            
            // Bold: **text** or __text__ (process first to avoid conflicts)
            html = html.replace(/\*\*([^*]+?)\*\*/g, '<strong>$1</strong>');
            html = html.replace(/__(.+?)__/g, '<strong>$1</strong>');
            
            // Italic: *text* or _text_ (avoid already processed bold)
            html = html.replace(/(?<!\*)\*([^*\n]+?)\*(?!\*)/g, '<em>$1</em>');
            html = html.replace(/(?<!_)_([^_\n]+?)_(?!_)/g, '<em>$1</em>');
            
            // Code blocks: ```code``` (process before inline code)
            html = html.replace(/```([\s\S]*?)```/g, function(match, code) {
                return '<pre><code>' + code.trim() + '</code></pre>';
            });
            
            // Inline code: `code` (but not inside code blocks)
            html = html.replace(/(?<!`)(?<!<code[^>]*>)`([^`\n]+?)`(?!`)/g, '<code>$1</code>');
            
            // Tables: | col1 | col2 |\n| --- | --- |\n| val1 | val2 |
            // Process tables before other formatting to preserve structure
            html = html.replace(/(\|[^\n]+\|(?:\n\|[^\n]+\|)+)/g, function(match) {
                const lines = match.trim().split('\n').filter(line => line.trim());
                if (lines.length < 2) return match; // Need at least header and separator
                
                // Check if second line is a separator (contains --- or ===)
                const separatorLine = lines[1].trim();
                if (!/^[\|\s\-=:]+$/.test(separatorLine)) {
                    return match; // Not a table
                }
                
                // Parse header row
                const headerCells = lines[0].split('|').map(cell => cell.trim()).filter(cell => cell);
                if (headerCells.length === 0) return match;
                
                let tableHTML = '<table><thead><tr>';
                headerCells.forEach(cell => {
                    tableHTML += '<th>' + cell + '</th>';
                });
                tableHTML += '</tr></thead><tbody>';
                
                // Parse data rows (skip separator line)
                for (let i = 2; i < lines.length; i++) {
                    const cells = lines[i].split('|').map(cell => cell.trim()).filter(cell => cell);
                    if (cells.length > 0) {
                        tableHTML += '<tr>';
                        cells.forEach(cell => {
                            tableHTML += '<td>' + cell + '</td>';
                        });
                        tableHTML += '</tr>';
                    }
                }
                
                tableHTML += '</tbody></table>';
                return tableHTML;
            });
            
            // Markdown links: [text](url) - process first
            html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function(match, text, url) {
                // Ensure URL has protocol
                let fullUrl = url.trim();
                if (!/^https?:\/\//i.test(fullUrl)) {
                    fullUrl = 'https://' + fullUrl;
                }
                return '<a href="' + fullUrl + '" target="_blank" rel="noopener noreferrer" class="ai-link">' + text + '</a>';
            });
            
            // Auto-detect and convert plain URLs to links (but not inside HTML tags)
            // First, protect existing HTML tags by temporarily replacing them
            const tagPlaceholders = [];
            let tagIndex = 0;
            html = html.replace(/<[^>]+>/g, function(match) {
                const placeholder = `__TAG_${tagIndex}__`;
                tagPlaceholders[tagIndex] = match;
                tagIndex++;
                return placeholder;
            });
            
            // Now convert URLs to links (https?:// and www.)
            // URLs are protected from being inside HTML tags since we replaced tags with placeholders
            html = html.replace(/(https?:\/\/[^\s<>"']+)/gi, function(match, url) {
                return '<a href="' + url + '" target="_blank" rel="noopener noreferrer" class="ai-link">' + url + '</a>';
            });
            
            // Also detect www. URLs and convert them (but not if already part of https://)
            html = html.replace(/(?<!https?:\/\/)(www\.[^\s<>"']+)/gi, function(match, url) {
                return '<a href="https://' + url + '" target="_blank" rel="noopener noreferrer" class="ai-link">' + url + '</a>';
            });
            
            // Restore HTML tags
            html = html.replace(/__TAG_(\d+)__/g, function(match, index) {
                return tagPlaceholders[parseInt(index)] || match;
            });
            
            // Lists: - or * or 1.
            html = html.replace(/^(\s*)[-*]\s+(.+)$/gm, '<li>$2</li>');
            html = html.replace(/^(\s*)\d+\.\s+(.+)$/gm, '<li>$2</li>');
            
            // Wrap consecutive list items in <ul>
            html = html.replace(/(<li>.*<\/li>\n?)+/g, function(match) {
                return '<ul>' + match + '</ul>';
            });
            
            // Line breaks (but preserve existing <br> tags and table structure)
            html = html.replace(/\n(?!<[h|u|l|p|d|t])/g, '<br>');
            
            return html;
        }

        // Function to add copy buttons to code blocks
        function addCopyButtonsToCodeBlocks(element) {
            const codeBlocks = element.querySelectorAll('pre code');
            codeBlocks.forEach((codeElement) => {
                const pre = codeElement.parentElement;
                // Check if this code block already has a copy button
                if (pre.querySelector('.code-copy-button')) {
                    return; // Already has copy button
                }
                
                // Create terminal-style header
                const header = document.createElement('div');
                header.className = 'code-block-header';
                
                const title = document.createElement('div');
                title.className = 'code-block-title';
                title.innerHTML = `
                    <span class="code-block-dot"></span>
                    <span class="code-block-dot"></span>
                    <span class="code-block-dot"></span>
                    <span style="margin-left: 8px;">Terminal</span>
                `;
                
                const copyButton = document.createElement('button');
                copyButton.className = 'code-copy-button';
                copyButton.innerHTML = `
                    <svg class="code-copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                    </svg>
                    <span>Copy</span>
                `;
                
                copyButton.addEventListener('click', () => {
                    const codeText = codeElement.textContent;
                    navigator.clipboard.writeText(codeText).then(() => {
                        copyButton.classList.add('copied');
                        const span = copyButton.querySelector('span');
                        if (span) span.textContent = 'Copied!';
                        setTimeout(() => {
                            copyButton.classList.remove('copied');
                            if (span) span.textContent = 'Copy';
                        }, 2000);
                    }).catch(err => {
                        console.error('Failed to copy:', err);
                    });
                });
                
                header.appendChild(title);
                header.appendChild(copyButton);
                
                // Insert header before code element
                pre.insertBefore(header, codeElement);
                pre.classList.add('code-block-wrapper');
            });
        }
        
        // Function to add collapsible sections for long content
        function addCollapsibleSections(element) {
            // Only add collapsible sections if content is long (more than 2000 characters)
            const textContent = element.textContent || element.innerText || '';
            if (textContent.length < 2000) {
                return; // Content is short, no need for collapsible sections
            }
            
            // Find all h2 and h3 headers and make their sections collapsible
            const headers = Array.from(element.querySelectorAll('h2, h3'));
            headers.forEach((header) => {
                // Skip if header is already inside a collapsible section
                if (header.closest('.collapsible-section')) {
                    return;
                }
                
                // Find the next header or end of content
                let nextHeader = header.nextElementSibling;
                while (nextHeader && !['H1', 'H2', 'H3'].includes(nextHeader.tagName)) {
                    nextHeader = nextHeader.nextElementSibling;
                }
                
                // Collect all content between this header and the next
                const sectionContent = document.createElement('div');
                sectionContent.className = 'collapsible-content';
                let current = header.nextSibling;
                const nodesToMove = [];
                
                while (current && current !== nextHeader) {
                    const next = current.nextSibling;
                    nodesToMove.push(current);
                    current = next;
                }
                
                // Move nodes to section content
                nodesToMove.forEach(node => {
                    sectionContent.appendChild(node);
                });
                
                // Only make collapsible if section has substantial content
                if (sectionContent.textContent.trim().length > 150 && nodesToMove.length > 0) {
                    // Store header text before removing it
                    const headerText = header.textContent;
                    
                    // Create collapsible wrapper
                    const wrapper = document.createElement('div');
                    wrapper.className = 'collapsible-section';
                    
                    // Create toggle button
                    const toggle = document.createElement('button');
                    toggle.className = 'collapsible-toggle';
                    toggle.setAttribute('aria-expanded', 'false'); // Closed by default
                    toggle.innerHTML = `
                        <svg class="toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                        <span class="toggle-text">${headerText}</span>
                    `;
                    
                    // Wrap content - closed by default
                    sectionContent.style.display = 'none';
                    
                    // Add click handler
                    toggle.addEventListener('click', () => {
                        const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
                        sectionContent.style.display = isExpanded ? 'none' : 'block';
                        toggle.setAttribute('aria-expanded', !isExpanded);
                    });
                    
                    wrapper.appendChild(toggle);
                    wrapper.appendChild(sectionContent);
                    
                    // Insert wrapper where header was, then remove the header (don't include it in content)
                    header.parentNode.insertBefore(wrapper, header);
                    header.remove(); // Remove header to avoid duplication
                }
            });
            
            // Make long lists collapsible (more than 8 items)
            const lists = Array.from(element.querySelectorAll('ul, ol'));
            lists.forEach(list => {
                const items = list.querySelectorAll('li');
                if (items.length > 8) {
                    const wrapper = document.createElement('div');
                    wrapper.className = 'collapsible-section';
                    
                    const toggle = document.createElement('button');
                    toggle.className = 'collapsible-toggle';
                    toggle.setAttribute('aria-expanded', 'false'); // Closed by default
                    const firstItems = Array.from(items).slice(0, 3).map(li => li.textContent.substring(0, 50)).join(', ');
                    toggle.innerHTML = `
                        <svg class="toggle-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                        <span class="toggle-text">Show ${items.length} items (${firstItems}...)</span>
                    `;
                    
                    const content = document.createElement('div');
                    content.className = 'collapsible-content';
                    content.appendChild(list.cloneNode(true));
                    content.style.display = 'none'; // Closed by default
                    
                    toggle.addEventListener('click', () => {
                        const isExpanded = toggle.getAttribute('aria-expanded') === 'true';
                        content.style.display = isExpanded ? 'none' : 'block';
                        toggle.setAttribute('aria-expanded', !isExpanded);
                    });
                    
                    wrapper.appendChild(toggle);
                    wrapper.appendChild(content);
                    list.parentNode.replaceChild(wrapper, list);
                }
            });
        }
        
        // Function to render charts from chart data blocks
        function renderCharts(element) {
            // Look for chart data in format: [CHART:type]...data...[/CHART]
            const chartRegex = /\[CHART:(\w+)\]([\s\S]*?)\[\/CHART\]/g;
            let match;
            let chartIndex = 0;
            const originalHTML = element.innerHTML;
            
            while ((match = chartRegex.exec(originalHTML)) !== null) {
                const chartType = match[1].toLowerCase();
                const chartData = match[2].trim();
                
                // Parse chart data (format: Labels: x,y,z\nData: 1,2,3 or JSON)
                let labels = [];
                let datasets = [];
                
                try {
                    // Try JSON format first
                    const jsonData = JSON.parse(chartData);
                    if (jsonData.labels && jsonData.data) {
                        labels = jsonData.labels;
                        datasets = [{ label: jsonData.label || 'Data', data: jsonData.data, backgroundColor: 'rgba(255, 255, 255, 0.2)', borderColor: 'rgba(255, 255, 255, 0.8)', borderWidth: 2 }];
                    }
                } catch (e) {
                    // Parse text format: Labels: x,y,z\nData: 1,2,3
                    const lines = chartData.split('\n');
                    lines.forEach(line => {
                        if (line.startsWith('Labels:')) {
                            labels = line.replace('Labels:', '').trim().split(',').map(l => l.trim());
                        } else if (line.startsWith('Data:')) {
                            const data = line.replace('Data:', '').trim().split(',').map(d => parseFloat(d.trim()));
                            datasets = [{ label: 'Data', data: data, backgroundColor: 'rgba(255, 255, 255, 0.2)', borderColor: 'rgba(255, 255, 255, 0.8)', borderWidth: 2 }];
                        }
                    });
                }
                
                if (labels.length > 0 && datasets.length > 0) {
                    // Create chart container
                    const chartId = 'chart-' + Date.now() + '-' + chartIndex++;
                    const chartContainer = document.createElement('div');
                    chartContainer.className = 'chart-container';
                    chartContainer.innerHTML = '<canvas id="' + chartId + '"></canvas>';
                    
                    // Replace the [CHART] block with the container
                    element.innerHTML = element.innerHTML.replace(match[0], chartContainer.outerHTML);
                    
                    // Wait for DOM to update, then create chart
                    setTimeout(() => {
                        const canvas = document.getElementById(chartId);
                        if (canvas && typeof Chart !== 'undefined') {
                            const ctx = canvas.getContext('2d');
                            new Chart(ctx, {
                                type: chartType === 'line' ? 'line' : chartType === 'pie' ? 'pie' : 'bar',
                                data: { labels: labels, datasets: datasets },
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: true,
                                    plugins: {
                                        legend: { labels: { color: '#ffffff' } }
                                    },
                                    scales: chartType !== 'pie' ? {
                                        x: { ticks: { color: '#ffffff' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } },
                                        y: { ticks: { color: '#ffffff' }, grid: { color: 'rgba(255, 255, 255, 0.1)' } }
                                    } : {}
                                }
                            });
                        }
                    }, 100);
                }
            }
        }

        // Audio element for typing sound
        const typingAudio = new Audio('Generative Typing.mp3');
        typingAudio.loop = true;
        typingAudio.volume = 0.3; // Set volume to 30%
        
        // Function to animate text with typewriter effect and white ball cursor
        function animateText(element, text, speed = 2) {
            logFrontend('Animation started', `text len: ${text.length}, speed: ${speed}ms`);
            element.innerHTML = '';
            element.classList.add('show');
            
            // Clear any previous animation timeouts
            animationTimeouts.forEach(timeout => clearTimeout(timeout));
            animationTimeouts = [];
            
            // Hide loading indicator and start animating send button
            // Add button doesn't need generating state
            sendButtonInner.classList.add('generating');
            isGenerating = true;
            
            // Start playing typing sound
            typingAudio.play().catch(e => {
                console.log('Audio play failed:', e);
            });
            
            // Parse markdown to get plain text with HTML tags
            const parsedHTML = parseMarkdown(text);
            
            // Create cursor element once and reuse it for smooth movement
            const cursor = document.createElement('span');
            cursor.className = 'typewriter-cursor';
            
            // Extract text character by character, preserving HTML structure
            let currentIndex = 0;
            let textToDisplay = '';
            
            function animateNext() {
                if (!isGenerating || currentIndex >= parsedHTML.length) {
                    // Animation complete - remove cursor
                    if (cursor.parentNode) {
                        cursor.remove();
                    }
                    logFrontend('Animation complete', `chars: ${currentIndex}`);
                    typingAudio.pause();
                    typingAudio.currentTime = 0;
                    // Add button doesn't need generating state
                    sendButtonInner.classList.remove('generating');
                    isGenerating = false;
                    
                    // Render any charts in the response
                    renderCharts(element);
                    
                    // Add copy buttons to code blocks
                    addCopyButtonsToCodeBlocks(element);
                    
                    // Add collapsible sections for long content
                    addCollapsibleSections(element);
                    
                    // Scroll page to bottom to show all content
                    window.scrollTo({
                        top: document.body.scrollHeight,
                        behavior: 'smooth'
                    });
                    return;
                }
                
                // Get the next character(s) - handle HTML tags
                let char = parsedHTML[currentIndex];
                
                // If we hit an HTML tag, skip to the end of it
                if (char === '<') {
                    const tagEnd = parsedHTML.indexOf('>', currentIndex);
                    if (tagEnd !== -1) {
                        // Include the entire tag at once
                        textToDisplay += parsedHTML.substring(currentIndex, tagEnd + 1);
                        currentIndex = tagEnd + 1;
                    } else {
                        textToDisplay += char;
                        currentIndex++;
                    }
                } else {
                    textToDisplay += char;
                    currentIndex++;
                }
                
                // Update the element with current text
                element.innerHTML = textToDisplay;
                
                // Add cursor after the text (it will smoothly move to new position via CSS transition)
                if (!cursor.parentNode) {
                    element.appendChild(cursor);
                } else {
                    // Cursor already exists, just move it to the end (smooth transition)
                    element.appendChild(cursor);
                }
                
                // Force reflow to ensure smooth transition
                void cursor.offsetWidth;
                
                // Smart auto-scroll: only scroll if user is already near the bottom
                const cursorRect = cursor.getBoundingClientRect();
                const cursorBottom = cursorRect.bottom;
                const viewportHeight = window.innerHeight;
                const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
                const documentHeight = document.documentElement.scrollHeight;
                const viewportBottom = scrollTop + viewportHeight;
                
                // Check if user is near the bottom of the page (within 200px)
                const isNearBottom = (documentHeight - viewportBottom) < 200;
                
                // Only auto-scroll if user is near bottom AND cursor is near bottom of viewport
                if (isNearBottom && cursorBottom > viewportHeight - 100) {
                    window.scrollBy({
                        top: cursorBottom - viewportHeight + 100,
                        behavior: 'smooth'
                    });
                }
                
                // Continue animation with faster speed for smoother effect
                const timeoutId = setTimeout(animateNext, Math.max(speed - 1, 1));
                animationTimeouts.push(timeoutId);
            }
            
            // Start animation
            animateNext();
        }
        
        // App name splitting animation
        function initializeAppNameAnimation() {
            const appName = document.querySelector('.app-name');
            if (!appName) return;
            
            const words = ['searchbar', 'that', 'knows', 'everything', 'about', 'you'];
            
            // Create the HTML structure with all word parts and dots
            function createWordStructure() {
                let html = '';
                words.forEach((word, index) => {
                    html += `<span class="word-part">${word}</span>`;
                    if (index < words.length - 1) {
                        html += `<span class="word-dot">•</span>`;
                    }
                });
                appName.innerHTML = html;
            }
            
            function runAnimation() {
                createWordStructure();
                
                const wordParts = appName.querySelectorAll('.word-part');
                const dots = appName.querySelectorAll('.word-dot');
                
                // After 2 seconds, start splitting words one by one
                setTimeout(() => {
                    appName.classList.add('split');
                    
                    // Split words one by one slowly and nicely
                    wordParts.forEach((wordPart, index) => {
                        // Calculate delay: first word starts immediately, then 1 second between each
                        const delay = index * 1000;
                        
                        setTimeout(() => {
                            // Add split class to this word part
                            wordPart.classList.add('split');
                        }, delay);
                    });
                    
                    // After all words are split, wait 2 seconds, then merge everything back
                    const totalSplitTime = (wordParts.length - 1) * 1000 + 800; // Last word transition time
                    setTimeout(() => {
                        // Wait 2 seconds after all words are split
                        setTimeout(() => {
                            // Remove split class from ALL words at the same time - this will hide all dots and merge words simultaneously
                            wordParts.forEach((wordPart) => {
                                wordPart.classList.remove('split');
                            });
                            
                            // Remove split class from parent at the same time
                            appName.classList.remove('split');
                            
                            // Wait for transitions to complete, then loop the animation
                            setTimeout(() => {
                                runAnimation();
                            }, 1000);
                         }, 2000); // Wait 2 seconds after all words are split
                     }, totalSplitTime);
                 }, 2000);
            }
            
            // Start the animation loop
            runAnimation();
        }
        
        const connectingLine = document.getElementById('connectingLine');
        const osintContainer = document.getElementById('osintContainer');
        const mainContainer = document.getElementById('mainContainer');
        const escHint = document.getElementById('escHint');
        const escLoading = document.getElementById('escLoading');
        let isProcessing = false;
        let animationEnabled = false;
        let currentInputValue = '';
        let currentBranches = [];
        let escHoldTimer = null;
        let escKeyDown = false;
        let animationTimeouts = [];

        function clearOSINT() {
            osintContainer.classList.remove('show');
            osintContainer.innerHTML = '';
            currentBranches.forEach(branch => branch.remove());
            currentBranches = [];
        }

        // Function to render conversation history
        function renderConversation() {
            let html = '';
            conversationHistory.forEach((msg, index) => {
                html += `<div class="message">`;
                // User message
                html += `<div class="message-user">`;
                html += `<div class="message-user-label">Me</div>`;
                html += `<div class="message-user-content">${escapeHtml(msg.user)}</div>`;
                html += `</div>`;
                // AI response
                if (msg.ai) {
                    html += `<div class="message-ai">`;
                    html += `<div class="message-ai-label">AI</div>`;
                    // Parse markdown for AI responses (except the last one which will be animated)
                    if (index === conversationHistory.length - 1) {
                        // Last message - will be animated, so just create empty container
                        html += `<div class="message-ai-content"></div>`;
                    } else {
                        // Previous messages - render with markdown
                        html += `<div class="message-ai-content">${parseMarkdown(msg.ai)}</div>`;
                    }
                    html += `</div>`;
                }
                html += `</div>`;
            });
            aiResponse.innerHTML = html;
            
            // Add copy buttons and collapsible sections to all rendered messages
            const allMessages = aiResponse.querySelectorAll('.message-ai-content');
            allMessages.forEach(msgElement => {
                addCopyButtonsToCodeBlocks(msgElement);
                addCollapsibleSections(msgElement);
            });
            
            if (conversationHistory.length > 0) {
                aiResponse.classList.add('show');
            }
            
            // Update example prompts visibility
            updateExamplePrompts();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        async function sendMessage() {
            const message = searchInput.value.trim();
            if (!message || isProcessing) return;

            logFrontend('Send message', `"${message.substring(0, 50)}${message.length > 50 ? '...' : ''}"`);

            // Hide example prompts when sending a message
            examplePrompts.classList.remove('show');

            // Add user message to history
            conversationHistory.push({ user: message, ai: null });
            renderConversation();
            
            connectingLine.classList.remove('show');
            clearOSINT();
            
            // Stop any playing typing audio
            typingAudio.pause();
            typingAudio.currentTime = 0;
            
            // Show loading indicator

            currentInputValue = message;
            searchInput.value = '';
            isProcessing = true;
            searchInput.disabled = true;
            // Add button doesn't need to be disabled
            sendButtonInner.disabled = true;

            // Create AbortController for cancellation
            currentAbortController = new AbortController();

            try {
                const data = await requestChat(message, currentAbortController.signal);
                console.log('Response data:', data); // Debug log
                console.log('Response status:', response.status); // Debug log
                
                // Show new chat button when we have a response
                const newChatButton = document.getElementById('newChatButton');
                if (newChatButton) {
                    newChatButton.classList.add('show');
                }
                
                let aiResponseText = '';
                if (data.type === 'ai_response' && data.response) {
                    aiResponseText = data.response;
                    logFrontend('AI response received', `len: ${data.response.length}`);
                } else if (data.reply) {
                    aiResponseText = data.reply;
                    logFrontend('AI reply received', `len: ${data.reply.length}`);
                } else if (data.type === 'osint_options' && data.options) {
                    // Show OSINT options as buttons
                    logFrontend('OSINT options', `count: ${data.options.length}`);
                    showOSINTOptions(data.options, data.input_value);
                    // Still add to history
                    if (conversationHistory.length > 0) {
                        conversationHistory[conversationHistory.length - 1].ai = 'OSINT options displayed';
                    }
                    renderConversation();
                    return;
                } else if (data.response) {
                    aiResponseText = data.response;
                    logFrontend('AI response (fallback)', `len: ${data.response.length}`);
                } else {
                    aiResponseText = 'Error: ' + (data.error || 'Unknown error. Response: ' + JSON.stringify(data));
                    logFrontend('Unexpected response format', JSON.stringify(data).substring(0, 100));
                }
                
                // Update the last message in history with AI response
                if (conversationHistory.length > 0) {
                    conversationHistory[conversationHistory.length - 1].ai = aiResponseText;
                }
                
                // Render conversation and animate the latest AI response
                renderConversation();
                const lastMessage = aiResponse.querySelector('.message:last-child .message-ai-content');
                if (lastMessage) {
                    // Clear and animate just the last AI response
                    lastMessage.innerHTML = '';
                    animateText(lastMessage, aiResponseText, 3);
                }
            } catch (error) {
                // Hide loading on error (unless it was aborted)
                if (error.name !== 'AbortError') {
                    logFrontend('Error', `${error.name}: ${error.message || 'Connection failed'}`);
                    // Add button doesn't need generating state
                    sendButtonInner.classList.remove('generating');
                    isGenerating = false;
                    // More specific error message
                    let errorMsg = 'Error: Could not connect to the server.';
                    if (error.message) {
                        errorMsg = `Error: ${error.message}`;
                    } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
                        errorMsg = 'Error: Server connection failed. Double-click start.bat (or run npm start) and open http://localhost:8080';
                    }
                    aiResponse.textContent = errorMsg;
                    aiResponse.classList.add('show');
                    console.error('Error:', error);
                } else {
                    // Request was cancelled
                    logFrontend('Request cancelled', 'User cancelled');
                    // Add button doesn't need generating state
                    sendButtonInner.classList.remove('generating');
                    isGenerating = false;
                    aiResponse.classList.remove('show');
                    aiResponse.innerHTML = '';
                }
            } finally {
                isProcessing = false;
                searchInput.disabled = false;
                // Add button doesn't need to be disabled
                sendButtonInner.disabled = false;
                currentAbortController = null;
                searchInput.focus();
            }
        }

        function showOSINTOptions(options, inputValue) {
            const buttonsContainer = document.createElement('div');
            buttonsContainer.className = 'osint-buttons';
            
            options.forEach(option => {
                const button = document.createElement('button');
                button.className = 'osint-button';
                button.textContent = option.name;
                button.onclick = () => showOSINTBranch(option.type, inputValue, button);
                buttonsContainer.appendChild(button);
            });
            
            osintContainer.appendChild(buttonsContainer);
            osintContainer.classList.add('show');
        }

        async function showOSINTBranch(resourceType, inputValue, buttonElement) {
            logFrontend('OSINT branch', `type: ${resourceType}, value: ${inputValue}`);
            // Remove existing branches
            currentBranches.forEach(branch => branch.remove());
            currentBranches = [];

            try {
                let data = { resources: getLocalOsintResources(resourceType, inputValue) };
                try {
                    const response = await fetch(API_BASE + '/osint-resources', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ type: resourceType, value: inputValue })
                    });
                    if (response.ok) {
                        const remote = await response.json();
                        if (remote.resources && remote.resources.length) data = remote;
                    }
                } catch (error) {
                    // Static GitHub Pages deploy uses local resource links.
                }
                
                if (data.resources && data.resources.length > 0) {
                    // Create branch
                    const branch = document.createElement('div');
                    branch.className = 'osint-branch';
                    
                    const rect = buttonElement.getBoundingClientRect();
                    branch.style.left = (rect.right + 20) + 'px';
                    branch.style.top = (rect.top) + 'px';
                    
                    data.resources.forEach(resource => {
                        const link = document.createElement('a');
                        link.className = 'osint-link';
                        link.href = resource.url;
                        link.target = '_blank';
                        link.textContent = resource.name;
                        branch.appendChild(link);
                    });
                    
                    document.body.appendChild(branch);
                    currentBranches.push(branch);
                    
                    // Animate branch appearance
                    setTimeout(() => {
                        branch.classList.add('show');
                    }, 50);
                }
            } catch (error) {
                console.error('Error fetching resources:', error);
            }
        }
        
        // Gravity typing physics system
        let fallingLetters = [];
        let animationFrameId = null;
        const GRAVITY = 0.5;
        const BOUNCE_DAMPING = 0.7; // Energy loss on bounce
        const LETTER_SIZE = 44; // Approximate letter size for collision detection (updated to match font-size)
        
        // Get ground Y position (bottom of viewport)
        function getGroundY() {
            return window.innerHeight - 5; // Ground even lower (closer to bottom)
        }
        
        function createFallingLetter(char) {
            const letter = document.createElement('div');
            letter.className = 'falling-letter';
            letter.textContent = char;
            
            // Random horizontal position
            const randomX = Math.random() * (window.innerWidth - 50);
            letter.style.left = randomX + 'px';
            letter.style.top = '0px';
            
            document.body.appendChild(letter);
            
            // Get letter dimensions
            const rect = letter.getBoundingClientRect();
            
            // Create physics object
            const letterObj = {
                element: letter,
                x: randomX,
                y: 0,
                vx: (Math.random() - 0.5) * 2, // Random horizontal velocity
                vy: 0, // Start with no vertical velocity
                width: rect.width,
                height: rect.height,
                rotation: 0,
                rotationSpeed: (Math.random() - 0.5) * 5
            };
            
            fallingLetters.push(letterObj);
            
            // Start animation loop if not already running
            if (!animationFrameId) {
                animateGravityLetters();
            }
            
            // Letters stay permanently - no timeout removal
        }
        
        function animateGravityLetters() {
            if (fallingLetters.length === 0) {
                if (animationFrameId) {
                    cancelAnimationFrame(animationFrameId);
                    animationFrameId = null;
                }
                return;
            }
            
            // Update each letter
            for (let i = 0; i < fallingLetters.length; i++) {
                const letter = fallingLetters[i];
                
                // Apply gravity
                letter.vy += GRAVITY;
                
                // Update position
                letter.y += letter.vy;
                letter.x += letter.vx;
                
                // Wall collisions (left and right) - check first
                if (letter.x < 0) {
                    letter.x = 0;
                    letter.vx *= -BOUNCE_DAMPING;
                }
                if (letter.x + letter.width > window.innerWidth) {
                    letter.x = window.innerWidth - letter.width;
                    letter.vx *= -BOUNCE_DAMPING;
                }
                
                // Ground collision - check for stacking on other letters first
                let highestStackY = getGroundY() - letter.height; // Default to ground level
                
                // Check all other letters to find the highest one we're stacking on
                for (let j = 0; j < fallingLetters.length; j++) {
                    if (i === j) continue;
                    const other = fallingLetters[j];
                    
                    // Check if this letter is above another letter horizontally
                    const horizontalOverlap = letter.x + letter.width > other.x && letter.x < other.x + other.width;
                    
                    if (horizontalOverlap) {
                        // Check if other letter is below and stopped
                        const otherIsStopped = Math.abs(other.vy) < 0.1 && Math.abs(other.vx) < 0.5;
                        const otherBottom = other.y + other.height;
                        
                        if (otherBottom < highestStackY && otherIsStopped) {
                            // This letter can stack on top of this other letter
                            highestStackY = otherBottom;
                        }
                    }
                }
                
                // Apply ground/stacking collision
                if (letter.y >= highestStackY) {
                    letter.y = highestStackY; // Stop at ground or on top of stack
                    if (letter.vy > 0) {
                        letter.vy *= -BOUNCE_DAMPING; // Bounce with damping
                        letter.vx *= 0.9; // Friction
                    }
                    // Only stop if actually on surface and velocity is very small
                    if (Math.abs(letter.vy) < 0.5 && letter.y >= highestStackY - 1) {
                        letter.vy = 0;
                        letter.vx *= 0.95; // More friction when on ground/stacked
                    }
                } else {
                    // Letter is NOT on ground - ensure it's falling
                    // If vy is 0 or negative while floating, apply gravity
                    if (letter.vy <= 0) {
                        letter.vy = GRAVITY;
                    }
                }
                
                // Update rotation
                const isOnGround = letter.y >= getGroundY() - letter.height;
                const isStopped = Math.abs(letter.vy) < 0.5 && Math.abs(letter.vx) < 0.5;
                
                if (!isOnGround || !isStopped) {
                    // Apply rotation damping when on ground
                    if (isOnGround) {
                        letter.rotationSpeed *= 0.95; // Slow down rotation on ground
                        if (Math.abs(letter.rotationSpeed) < 0.1) {
                            letter.rotationSpeed = 0; // Stop rotation completely
                        }
                    }
                    letter.rotation += letter.rotationSpeed;
                } else {
                    // Stop rotation completely when on ground and stopped
                    letter.rotationSpeed = 0;
                }
                
                // Collision detection with other letters using bounding box (AABB)
                for (let j = 0; j < fallingLetters.length; j++) {
                    if (i === j) continue;
                    const other = fallingLetters[j];
                    
                    // Bounding box collision detection
                    const letterLeft = letter.x;
                    const letterRight = letter.x + letter.width;
                    const letterTop = letter.y;
                    const letterBottom = letter.y + letter.height;
                    
                    const otherLeft = other.x;
                    const otherRight = other.x + other.width;
                    const otherTop = other.y;
                    const otherBottom = other.y + other.height;
                    
                    // Check if bounding boxes overlap
                    const horizontalOverlap = letterRight > otherLeft && letterLeft < otherRight;
                    const verticalOverlap = letterBottom > otherTop && letterTop < otherBottom;
                    
                    if (horizontalOverlap && verticalOverlap) {
                        // Collision detected - bounce and separate
                        const letterIsFalling = letter.vy > 0.1; // Letter is moving down
                        const otherIsStopped = Math.abs(other.vy) < 0.1 && Math.abs(other.vx) < 0.5; // Other is stopped
                        const letterIsStopped = Math.abs(letter.vy) < 0.1 && Math.abs(letter.vx) < 0.5;
                        const otherIsFalling = other.vy > 0.1;
                        
                        // Stacking logic: if one is falling onto a stopped one, stack it
                        // Only stack if the falling letter is actually above the stopped one
                        if (letterIsFalling && otherIsStopped && letter.y < other.y && letter.y + letter.height <= other.y + 5) {
                            // Letter is falling onto stopped other - stack on top
                            letter.y = otherTop - letter.height;
                            // Only stop if actually on top
                            if (letter.y <= otherTop) {
                                letter.vy = 0;
                            }
                            letter.vx *= 0.8; // Reduce horizontal velocity
                            letter.rotationSpeed *= 0.9; // Slow rotation
                        } else if (otherIsFalling && letterIsStopped && other.y < letter.y && other.y + other.height <= letter.y + 5) {
                            // Other is falling onto stopped letter - stack on top
                            other.y = letterTop - other.height;
                            // Only stop if actually on top
                            if (other.y <= letterTop) {
                                other.vy = 0;
                            }
                            other.vx *= 0.8;
                            other.rotationSpeed *= 0.9;
                        } else {
                            // Both moving - bounce off each other with proper physics
                            const dx = (letter.x + letter.width / 2) - (other.x + other.width / 2);
                            const dy = (letter.y + letter.height / 2) - (other.y + other.height / 2);
                            const distance = Math.sqrt(dx * dx + dy * dy);
                            
                            if (distance > 0) {
                                // Normalize direction
                                const nx = dx / distance;
                                const ny = dy / distance;
                                
                                // Relative velocity
                                const dvx = letter.vx - other.vx;
                                const dvy = letter.vy - other.vy;
                                
                                // Relative velocity along collision normal
                                const dotProduct = dvx * nx + dvy * ny;
                                
                                // Only resolve if objects are moving towards each other
                                if (dotProduct < 0) {
                                    // Calculate separation distance
                                    const minDistance = (letter.width + other.width) / 2;
                                    const overlap = minDistance - distance;
                                    
                                    if (overlap > 0) {
                                        // Separate letters to prevent overlap
                                        const separationX = (nx * overlap) / 2;
                                        const separationY = (ny * overlap) / 2;
                                        letter.x += separationX;
                                        letter.y += separationY;
                                        other.x -= separationX;
                                        other.y -= separationY;
                                        
                                        // Apply bounce with damping
                                        const bounce = dotProduct * BOUNCE_DAMPING;
                                        letter.vx -= bounce * nx;
                                        letter.vy -= bounce * ny;
                                        other.vx += bounce * nx;
                                        other.vy += bounce * ny;
                                        
                                        // Ensure letters continue falling after bounce (unless on ground)
                                        if (letter.vy <= 0 && letter.y < getGroundY() - letter.height) {
                                            letter.vy = GRAVITY;
                                        }
                                        if (other.vy <= 0 && other.y < getGroundY() - other.height) {
                                            other.vy = GRAVITY;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Final check: ensure letter is falling if not on ground
                const finalGroundY = getGroundY() - letter.height;
                if (letter.y < finalGroundY && letter.vy <= 0) {
                    letter.vy = GRAVITY;
                }
                
                // Update DOM
                letter.element.style.left = letter.x + 'px';
                letter.element.style.top = letter.y + 'px';
                letter.element.style.transform = `rotate(${letter.rotation}deg)`;
            }
            
            animationFrameId = requestAnimationFrame(animateGravityLetters);
        }

        // Function to clear all falling letters
        function clearAllFallingLetters() {
            // Cancel animation frame
            if (animationFrameId) {
                cancelAnimationFrame(animationFrameId);
                animationFrameId = null;
            }
            
            // Remove all letter elements from DOM
            fallingLetters.forEach(letter => {
                if (letter.element && letter.element.parentNode) {
                    letter.element.parentNode.removeChild(letter.element);
                }
            });
            
            // Clear the array
            fallingLetters = [];
        }
        
        animationToggle.addEventListener('change', (e) => {
            animationEnabled = e.target.checked;
            logFrontend('Animation toggle', animationEnabled ? 'ON' : 'OFF');
            
            // Clear all letters when toggle is turned off
            if (!animationEnabled) {
                clearAllFallingLetters();
            }
        });
        
        // Gravity mode for UI elements
        let gravityModeEnabled = false;
        let uiElements = [];
        let uiGravityFrameId = null;
        const UI_GRAVITY = 0; // Zero gravity - elements float
        const UI_BOUNCE_DAMPING = 0.85; // Bounce damping - higher = less energy loss
        const MIN_VELOCITY = 0.1; // Minimum velocity threshold - stop very slow movements
        
        function getUIElements() {
            const elements = [
                { element: document.querySelector('.app-name'), name: 'app-name' },
                { element: document.querySelector('.search-input-wrapper'), name: 'search-bar' },
                { element: document.querySelector('.send-button-inner'), name: 'send-button-inner' },
                { element: document.querySelector('.more-options-button'), name: 'more-options' },
                { element: document.querySelector('.add-button'), name: 'add-button' },
                { element: document.querySelector('.example-prompts'), name: 'example-prompts' },
                { element: document.querySelector('.new-chat-button'), name: 'new-chat' },
                { element: document.querySelector('.esc-hint'), name: 'esc-hint' }
                // Exclude ai-response and main-container - they contain chat messages which should not have gravity
            ];
            
            // Filter out null elements and exclude toggle containers and chat messages
            return elements.filter(item => {
                if (!item.element) return false;
                // Exclude toggle containers - they should stay fixed and visible
                if (item.element.closest('.toggle-container')) return false;
                // Exclude chat messages - they should not have gravity
                if (item.element.classList.contains('message-user') || 
                    item.element.classList.contains('message-ai') ||
                    item.element.closest('.message-user') ||
                    item.element.closest('.message-ai')) {
                    return false;
                }
                return true;
            });
        }
        
        function initializeUIElements() {
            uiElements = getUIElements().map(item => {
                // Get current position BEFORE making any changes
                const rect = item.element.getBoundingClientRect();
                const computedStyle = window.getComputedStyle(item.element);
                
                // Store the EXACT current visual position
                const currentX = rect.left;
                const currentY = rect.top;
                const currentWidth = rect.width || 50;
                const currentHeight = rect.height || 50;
                
                // Store original styles for restoration
                const originalPosition = {
                    position: computedStyle.position,
                    top: computedStyle.top,
                    left: computedStyle.left,
                    transform: computedStyle.transform,
                    margin: computedStyle.margin
                };
                
                // Set fixed position WITHOUT changing the visual location
                // This preserves the exact position the element is currently at
                // Set position synchronously to prevent any visual jumps
                item.element.style.transition = 'none'; // Disable transitions FIRST
                item.element.style.position = 'fixed';
                item.element.style.top = currentY + 'px';
                item.element.style.left = currentX + 'px';
                item.element.style.transform = 'none';
                item.element.style.margin = '0';
                
                // Verify position was set correctly
                const verifyRect = item.element.getBoundingClientRect();
                if (Math.abs(verifyRect.left - currentX) > 1 || Math.abs(verifyRect.top - currentY) > 1) {
                    // If position changed, correct it
                    item.element.style.top = currentY + 'px';
                    item.element.style.left = currentX + 'px';
                }
                
                return {
                    element: item.element,
                    name: item.name,
                    x: currentX, // Use exact current position
                    y: currentY,  // Use exact current position
                    vx: (Math.random() - 0.5) * 3, // Random horizontal velocity
                    vy: (Math.random() - 0.5) * 3, // Random vertical velocity for floating
                    width: currentWidth,
                    height: currentHeight,
                    originalPosition: originalPosition
                };
            });
        }
        
        function animateUIGravity() {
            if (!gravityModeEnabled || uiElements.length === 0) {
                if (uiGravityFrameId) {
                    cancelAnimationFrame(uiGravityFrameId);
                    uiGravityFrameId = null;
                }
                return;
            }
            
            const screenWidth = window.innerWidth;
            const screenHeight = window.innerHeight;
            
            for (let i = 0; i < uiElements.length; i++) {
                const ui = uiElements[i];
                
                // Skip toggle containers - they should stay fixed and visible
                if (ui.element.closest('.toggle-container')) {
                    continue;
                }
                
                // Skip chat messages and ai-response container - they should not have gravity
                if (ui.element.classList.contains('message-user') || 
                    ui.element.classList.contains('message-ai') ||
                    ui.element.classList.contains('message') ||
                    ui.element.closest('.message-user') ||
                    ui.element.closest('.message-ai') ||
                    ui.element.closest('.message') ||
                    ui.element.id === 'aiResponse') {
                    continue;
                }
                
                // Update element dimensions - get accurate hitbox from actual element
                const rect = ui.element.getBoundingClientRect();
                
                // Use actual bounding box dimensions for accurate collision detection
                if (rect.width > 0 && !isNaN(rect.width)) {
                    ui.width = Math.min(rect.width, screenWidth);
                } else if (ui.width <= 0 || isNaN(ui.width)) {
                    // Fallback: use stored width or default
                    ui.width = ui.width > 0 ? ui.width : 50;
                }
                
                if (rect.height > 0 && !isNaN(rect.height)) {
                    ui.height = Math.min(rect.height, screenHeight);
                } else if (ui.height <= 0 || isNaN(ui.height)) {
                    // Fallback: use stored height or default
                    ui.height = ui.height > 0 ? ui.height : 50;
                }
                
                // Ensure width/height are valid and reasonable
                ui.width = Math.max(10, Math.min(ui.width, screenWidth));
                ui.height = Math.max(10, Math.min(ui.height, screenHeight));
                
                // Zero gravity - no vertical acceleration, elements float
                // Apply slight friction to prevent infinite movement
                ui.vx *= 0.999;
                ui.vy *= 0.999;
                
                // Stop very slow movements to prevent jitter
                if (Math.abs(ui.vx) < MIN_VELOCITY) ui.vx = 0;
                if (Math.abs(ui.vy) < MIN_VELOCITY) ui.vy = 0;
                
                // PREDICTIVE COLLISION DETECTION - check before moving
                // Calculate next position
                const nextX = ui.x + ui.vx;
                const nextY = ui.y + ui.vy;
                const nextRightEdge = nextX + ui.width;
                const nextBottomEdge = nextY + ui.height;
                
                // Check for collisions BEFORE updating position
                let bouncedX = false;
                let bouncedY = false;
                
                // LEFT edge collision (predictive)
                if (nextX < 0) {
                    ui.x = 0;
                    ui.vx = Math.abs(ui.vx) * UI_BOUNCE_DAMPING; // Bounce right with damping
                    bouncedX = true;
                }
                // RIGHT edge collision (predictive)
                else if (nextRightEdge > screenWidth) {
                    ui.x = screenWidth - ui.width;
                    ui.vx = -Math.abs(ui.vx) * UI_BOUNCE_DAMPING; // Bounce left with damping
                    bouncedX = true;
                } else {
                    // No X collision, update position normally
                    ui.x = nextX;
                }
                
                // TOP edge collision (predictive)
                if (nextY < 0) {
                    ui.y = 0;
                    ui.vy = Math.abs(ui.vy) * UI_BOUNCE_DAMPING; // Bounce down with damping
                    bouncedY = true;
                }
                // BOTTOM edge collision (predictive)
                else if (nextBottomEdge > screenHeight) {
                    ui.y = screenHeight - ui.height;
                    ui.vy = -Math.abs(ui.vy) * UI_BOUNCE_DAMPING; // Bounce up with damping
                    bouncedY = true;
                } else {
                    // No Y collision, update position normally
                    ui.y = nextY;
                }
                
                // If we bounced, ensure we're exactly at the boundary
                if (bouncedX) {
                    ui.x = Math.max(0, Math.min(ui.x, screenWidth - ui.width));
                }
                if (bouncedY) {
                    ui.y = Math.max(0, Math.min(ui.y, screenHeight - ui.height));
                }
                
                // Final safety clamp to exact screen edges (double-check)
                const finalRightEdge = ui.x + ui.width;
                const finalBottomEdge = ui.y + ui.height;
                
                if (ui.x < 0) {
                    ui.x = 0;
                    if (!bouncedX) ui.vx = Math.abs(ui.vx) * UI_BOUNCE_DAMPING;
                }
                if (finalRightEdge > screenWidth) {
                    ui.x = screenWidth - ui.width;
                    if (!bouncedX) ui.vx = -Math.abs(ui.vx) * UI_BOUNCE_DAMPING;
                }
                if (ui.y < 0) {
                    ui.y = 0;
                    if (!bouncedY) ui.vy = Math.abs(ui.vy) * UI_BOUNCE_DAMPING;
                }
                if (finalBottomEdge > screenHeight) {
                    ui.y = screenHeight - ui.height;
                    if (!bouncedY) ui.vy = -Math.abs(ui.vy) * UI_BOUNCE_DAMPING;
                }
                
                // Ensure buttons stay visible with high z-index
                if (ui.name.includes('button') || ui.name === 'more-options' || ui.name === 'add-button') {
                    ui.element.style.zIndex = '9999';
                }
                
                // Update DOM - ensure fixed positioning and remove transforms/transitions
                // Always set these properties to ensure consistency
                ui.element.style.position = 'fixed';
                ui.element.style.top = Math.round(ui.y * 100) / 100 + 'px'; // Round to prevent sub-pixel issues
                ui.element.style.left = Math.round(ui.x * 100) / 100 + 'px'; // Round to prevent sub-pixel issues
                ui.element.style.transform = 'none';
                ui.element.style.transition = 'none'; // Disable transitions during gravity
                
                // For app-name and search-bar, remove parent container constraints
                if (ui.name === 'app-name' || ui.name === 'search-bar') {
                    ui.element.style.margin = '0';
                    // Ensure they're independent from parent container
                    const parent = ui.element.parentElement;
                    if (parent && parent.classList.contains('main-container')) {
                        // Make sure parent doesn't constrain positioning
                        parent.style.position = 'static';
                    }
                }
                
                // For example-prompts, ensure it floats properly
                if (ui.name === 'example-prompts') {
                    ui.element.style.margin = '0';
                    ui.element.style.pointerEvents = 'auto'; // Keep it interactive
                    // Remove any transform that might interfere
                    ui.element.style.transform = 'none';
                }
            }
            
            uiGravityFrameId = requestAnimationFrame(animateUIGravity);
        }
        
        function resetUIElements() {
            uiElements.forEach(ui => {
                const orig = ui.originalPosition;
                ui.element.style.position = orig.position;
                ui.element.style.top = orig.top;
                ui.element.style.left = orig.left;
                ui.element.style.transform = orig.transform;
            });
            
            if (uiGravityFrameId) {
                cancelAnimationFrame(uiGravityFrameId);
                uiGravityFrameId = null;
            }
            
            uiElements = [];
        }
        
        if (gravityToggle) {
            gravityToggle.addEventListener('change', (e) => {
                gravityModeEnabled = e.target.checked;
                logFrontend('Zero gravity mode', gravityModeEnabled ? 'ON' : 'OFF');
                
                if (gravityModeEnabled) {
                    // Prevent scrolling when gravity mode is enabled
                    document.body.style.overflow = 'hidden';
                    document.documentElement.style.overflow = 'hidden';
                    document.body.style.maxHeight = '100vh';
                    document.documentElement.style.maxHeight = '100vh';
                    
                    initializeUIElements();
                    animateUIGravity();
                } else {
                    // Restore scrolling when gravity mode is disabled
                    document.body.style.overflow = '';
                    document.documentElement.style.overflow = '';
                    document.body.style.maxHeight = '';
                    document.documentElement.style.maxHeight = '';
                    
                    resetUIElements();
                }
            });
            
            // Bubble toggle - navigate to bubble.html when toggled on
            bubbleToggle.addEventListener('change', (e) => {
                if (e.target.checked) {
                    window.location.href = 'bubble.html';
                }
            });
        }
        
        // Re-clamp elements when window is resized
        window.addEventListener('resize', () => {
            if (gravityModeEnabled && uiElements.length > 0) {
                const screenWidth = window.innerWidth;
                const screenHeight = window.innerHeight;
                
                uiElements.forEach(ui => {
                    // Skip toggle containers and chat messages
                    if (ui.element.closest('.toggle-container') ||
                        ui.element.classList.contains('message-user') || 
                        ui.element.classList.contains('message-ai') ||
                        ui.element.closest('.message-user') ||
                        ui.element.closest('.message-ai') ||
                        ui.element.id === 'aiResponse') {
                        return;
                    }
                    
                    // Update dimensions
                    const rect = ui.element.getBoundingClientRect();
                    if (rect.width > 0 && !isNaN(rect.width)) {
                        ui.width = Math.min(rect.width, screenWidth);
                    }
                    if (rect.height > 0 && !isNaN(rect.height)) {
                        ui.height = Math.min(rect.height, screenHeight);
                    }
                    
                    // Recalculate bounds
                    const maxX = Math.max(0, screenWidth - ui.width);
                    const maxY = Math.max(0, screenHeight - ui.height);
                    
                    // Clamp position to new bounds
                    ui.x = Math.max(0, Math.min(ui.x, maxX));
                    ui.y = Math.max(0, Math.min(ui.y, maxY));
                });
            }
        });
        
        // Explosion effect function
        function triggerExplosion() {
            if (fallingLetters.length === 0) return;
            
            // Calculate center point (middle of screen or search bar position)
            const centerX = window.innerWidth / 2;
            const centerY = window.innerHeight / 2;
            
            // Apply explosion force to all letters
            fallingLetters.forEach(letter => {
                // Calculate direction from center to letter
                const dx = letter.x - centerX;
                const dy = letter.y - centerY;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                // Normalize direction
                const dirX = distance > 0 ? dx / distance : (Math.random() - 0.5);
                const dirY = distance > 0 ? dy / distance : (Math.random() - 0.5);
                
                // Random explosion force (high velocity)
                const explosionForce = 15 + Math.random() * 20; // 15-35 speed
                
                // Apply explosion velocity
                letter.vx = dirX * explosionForce + (Math.random() - 0.5) * 5; // Add some randomness
                letter.vy = dirY * explosionForce + (Math.random() - 0.5) * 5;
                
                // Increase rotation speed for crazy spinning
                letter.rotationSpeed = (Math.random() - 0.5) * 30; // Much faster rotation
            });
        }
        
        // Explosion effect for UI elements
        function triggerUIExplosion(centerX, centerY) {
            if (!gravityModeEnabled || uiElements.length === 0) return;
            
            const screenWidth = window.innerWidth;
            const screenHeight = window.innerHeight;
            
            uiElements.forEach(ui => {
                // Skip toggle containers and chat messages
                if (ui.element.closest('.toggle-container') ||
                    ui.element.classList.contains('message-user') || 
                    ui.element.classList.contains('message-ai') ||
                    ui.element.closest('.message-user') ||
                    ui.element.closest('.message-ai') ||
                    ui.element.id === 'aiResponse') {
                    return;
                }
                
                // Calculate direction from click to element center
                const elementCenterX = ui.x + ui.width / 2;
                const elementCenterY = ui.y + ui.height / 2;
                const dx = elementCenterX - centerX;
                const dy = elementCenterY - centerY;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                // Normalize direction
                const dirX = distance > 0 ? dx / distance : (Math.random() - 0.5);
                const dirY = distance > 0 ? dy / distance : (Math.random() - 0.5);
                
                // Random explosion force (high velocity, but limited to prevent going off-screen)
                const explosionForce = 15 + Math.random() * 20; // 15-35 speed (reduced from 20-50)
                
                // Apply explosion velocity
                ui.vx = dirX * explosionForce + (Math.random() - 0.5) * 6;
                ui.vy = dirY * explosionForce + (Math.random() - 0.5) * 6;
                
                // Limit velocity to prevent elements from going too far off-screen
                const maxVelocity = 40;
                ui.vx = Math.max(-maxVelocity, Math.min(maxVelocity, ui.vx));
                ui.vy = Math.max(-maxVelocity, Math.min(maxVelocity, ui.vy));
            });
        }
        
        // Click to explode
        document.addEventListener('click', (e) => {
            const target = e.target;
            const centerX = e.clientX;
            const centerY = e.clientY;
            
            // Don't explode if clicking on interactive elements
            if (target.closest('#searchInput') || 
                target.closest('.send-button') || 
                target.closest('.send-button-inner') || 
                target.closest('.more-options-button') ||
                target.closest('.add-button') ||
                target.closest('.toggle-container') ||
                target.closest('button') ||
                target.closest('input')) {
                return;
            }
            
            // Explode falling letters if animation is enabled
            if (animationEnabled && fallingLetters.length > 0) {
                // Apply explosion from click position
                fallingLetters.forEach(letter => {
                    // Calculate direction from click to letter
                    const dx = letter.x - centerX;
                    const dy = letter.y - centerY;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    
                    // Normalize direction
                    const dirX = distance > 0 ? dx / distance : (Math.random() - 0.5);
                    const dirY = distance > 0 ? dy / distance : (Math.random() - 0.5);
                    
                    // Random explosion force (high velocity)
                    const explosionForce = 15 + Math.random() * 20; // 15-35 speed
                    
                    // Apply explosion velocity
                    letter.vx = dirX * explosionForce + (Math.random() - 0.5) * 5;
                    letter.vy = dirY * explosionForce + (Math.random() - 0.5) * 5;
                    
                    // Increase rotation speed for crazy spinning
                    letter.rotationSpeed = (Math.random() - 0.5) * 30;
                });
            }
            
            // Explode UI elements if gravity mode is enabled
            if (gravityModeEnabled) {
                triggerUIExplosion(centerX, centerY);
            }
        });

        let lastValue = '';
        
        // Initialize main container position to center (no animation)
        function initializeMainPosition(animate = false) {
            if (!animate) {
                mainContainer.classList.remove('animate');
            } else {
                // Ensure animation is enabled for smooth return
                mainContainer.classList.add('animate');
            }
            mainContainer.style.top = '50%';
            mainContainer.style.transform = 'translate(-50%, -50%)';
            mainContainer.classList.remove('typing');
            // Always hide ESC hint when returning to center
            escHint.classList.remove('show');
            escLoading.classList.remove('active');
            if (!animate) {
                // Enable animation after a brief delay
                setTimeout(() => {
                    mainContainer.classList.add('animate');
                }, 50);
            }
        }
        
        function repositionToBottom() {
            mainContainer.classList.add('animate');
            const containerHeight = mainContainer.offsetHeight;
            const escHintHeight = 30;
            // Use visual viewport height on mobile for better accuracy
            const viewportHeight = window.visualViewport ? window.visualViewport.height : window.innerHeight;
            // Adjust spacing for mobile (smaller screens need less space)
            const isMobile = window.innerWidth <= 768;
            const isSmallMobile = window.innerWidth <= 480;
            // Increased bottom spacing on mobile to account for scaled search bar and buttons
            const bottomSpacing = isSmallMobile ? 60 : isMobile ? 50 : 60;
            const bottomPosition = viewportHeight - containerHeight - escHintHeight - bottomSpacing;
            mainContainer.style.top = Math.max(bottomPosition, 20) + 'px'; // Ensure minimum 20px from top
            mainContainer.style.transform = 'translateX(-50%)';
            
            // Show divider and adjust AI response padding
            if (searchBarDivider) {
                searchBarDivider.classList.add('show');
            }
            updateAIResponsePadding();
        }
        
        function updateAIResponsePadding() {
            if (!aiResponse || !mainContainer.classList.contains('typing')) {
                return;
            }
            
            // Use requestAnimationFrame to ensure layout is calculated
            requestAnimationFrame(() => {
                // Calculate the space needed above the search bar
                const containerRect = mainContainer.getBoundingClientRect();
                const viewportHeight = window.visualViewport ? window.visualViewport.height : window.innerHeight;
                const spaceAboveSearchBar = viewportHeight - containerRect.top;
                
                // Set padding-bottom to ensure content doesn't go behind search bar
                // Add extra padding for safety (80px buffer for buttons and spacing)
                const paddingBottom = Math.max(spaceAboveSearchBar + 80, 250);
                aiResponse.style.paddingBottom = paddingBottom + 'px';
            });
        }
        
        // Update padding on scroll to handle dynamic content
        window.addEventListener('scroll', () => {
            if (mainContainer.classList.contains('typing')) {
                updateAIResponsePadding();
            }
        }, { passive: true });
        
        // Return to center smoothly from current position
        function returnToCenter() {
            mainContainer.classList.add('animate');
            mainContainer.style.top = '50%';
            mainContainer.style.transform = 'translate(-50%, -50%)';
            mainContainer.classList.remove('typing');
            searchInputWrapper.classList.remove('typing');
            // Always hide ESC hint when returning to center
            escHint.classList.remove('show');
            escLoading.classList.remove('active');
            // Hide buttons when returning to center
            addButton?.classList.remove('show');
            moreOptionsButton.classList.remove('show');
            searchInput.style.width = '100%';
            
            // Hide divider when returning to center
            if (searchBarDivider) {
                searchBarDivider.classList.remove('show');
            }
            // Reset AI response padding
            if (aiResponse) {
                aiResponse.style.paddingBottom = '150px';
            }
        }

        // Initialize on load (no animation)
        window.addEventListener('load', () => {
            initializeMainPosition(false);
            initializeAppNameAnimation();
            // Ensure example prompts are hidden on page load
            if (examplePrompts) {
                examplePrompts.classList.remove('show');
            }
        });
        
        window.addEventListener('resize', () => {
            const hasInput = searchInput.value.length > 0;
            const isTyping = mainContainer.classList.contains('typing');
            
            if (!hasInput && !isTyping) {
                // No input and not typing - return to center
                initializeMainPosition(false);
            } else if (hasInput || isTyping) {
                // Has input or is in typing mode - reposition to bottom
                repositionToBottom();
            }
            // Update padding on resize
            if (isTyping) {
                updateAIResponsePadding();
            }
        });

        // Handle mobile viewport changes (e.g., when address bar shows/hides)
        if (window.visualViewport) {
            window.visualViewport.addEventListener('resize', () => {
                const hasInput = searchInput.value.length > 0;
                const isTyping = mainContainer.classList.contains('typing');
                
                if (hasInput || isTyping) {
                    repositionToBottom();
                }
                // Update padding on viewport resize
                if (isTyping) {
                    updateAIResponsePadding();
                }
            });
        }

        searchInput.addEventListener('input', (e) => {
            const currentValue = searchInput.value;
            
            // Move main container to bottom and make search bar bigger when typing starts
            if (currentValue.length > 0 && lastValue.length === 0) {
                logFrontend('Typing started', `char: "${currentValue[0]}"`);
                repositionToBottom();
                mainContainer.classList.add('typing');
                searchInputWrapper.classList.add('typing');
                escHint.classList.add('show');
                
                // Ensure inner button is visible immediately
                ensureInnerButtonVisible();
                
                // Ensure inner button is visible immediately
                ensureInnerButtonVisible();
                
                // Show buttons with animation
                setTimeout(() => {
                    addButton?.classList.add('show');
                    moreOptionsButton.classList.add('show');
                    // Adjust input width based on screen size (account for outer buttons, inner button stays visible)
                    const isMobile = window.innerWidth <= 768;
                    const isSmallMobile = window.innerWidth <= 480;
                    if (isSmallMobile) {
                        searchInput.style.width = 'calc(100% - 100px)'; // Less space for smaller buttons
                    } else if (isMobile) {
                        searchInput.style.width = 'calc(100% - 110px)'; // Slightly less for mobile
                    } else {
                        searchInput.style.width = 'calc(100% - 120px)'; // Desktop
                    }
                    // Ensure inner button stays visible
                    ensureInnerButtonVisible();
                    // Update padding after layout settles
                    updateAIResponsePadding();
                    // Double check inner button after layout
                    setTimeout(ensureInnerButtonVisible, 100);
                }, 50);
            } else if (currentValue.length === 0 && lastValue.length > 0) {
                // Only return to center if there's no conversation history
                if (conversationHistory.length === 0) {
                    logFrontend('Input cleared', 'Returning to center (no chat history)');
                    initializeMainPosition(true);
                    searchInputWrapper.classList.remove('typing');
                    escHint.classList.remove('show');
                    
                    // Hide buttons with animation
                    addButton?.classList.remove('show');
                    moreOptionsButton.classList.remove('show');
                    searchInput.style.width = '100%';
                    
                    // Clear AI response when input is cleared and no history
                    aiResponse.classList.remove('show');
                    aiResponse.innerHTML = '';
                    // Add button doesn't need generating state
                    sendButtonInner.classList.remove('generating');
                    typingAudio.pause();
                    typingAudio.currentTime = 0;
                    clearOSINT();
                } else {
                    logFrontend('Input cleared', `Staying in chat view (has ${conversationHistory.length} messages)`);
                    // Keep container at bottom position when there's conversation history
                    repositionToBottom();
                    // Keep typing class to maintain bottom position styling
                    mainContainer.classList.add('typing');
                    
                    // Keep search bar expanded (typing state) when there's conversation history
                    searchInputWrapper.classList.add('typing');
                    escHint.classList.remove('show');
                    
                    // Keep buttons visible so user can continue asking
                    addButton?.classList.add('show');
                    moreOptionsButton.classList.add('show');
                    // Adjust input width based on screen size (account for outer buttons, inner button stays visible)
                    const isMobile = window.innerWidth <= 768;
                    const isSmallMobile = window.innerWidth <= 480;
                    if (isSmallMobile) {
                        searchInput.style.width = 'calc(100% - 100px)';
                    } else if (isMobile) {
                        searchInput.style.width = 'calc(100% - 110px)';
                    } else {
                        searchInput.style.width = 'calc(100% - 120px)';
                    }
                    // Ensure inner button stays visible
                    ensureInnerButtonVisible();
                    
                    // Update padding to prevent overlap
                    setTimeout(() => {
                        updateAIResponsePadding();
                    }, 50);
                    
                    // Don't clear AI response or conversation history
                    clearOSINT();
                }
            }
            
            // Check if a new character was added and animation is enabled
            if (currentValue.length > lastValue.length && animationEnabled) {
                const newChar = currentValue[currentValue.length - 1];
                if (newChar && newChar !== ' ') {
                    createFallingLetter(newChar);
                }
            }
            
            // Update example prompts after all state changes
            setTimeout(() => {
                updateExamplePrompts();
            }, 50);
            
            lastValue = currentValue;
        });

        // ESC key handler - hold for 1 second to return to main screen
        let escHoldStartTime = 0;
        const ESC_HOLD_TIME = 1000; // 1 second
        const ESC_MIN_HOLD = 300; // Minimum 300ms before release is allowed
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !escKeyDown) {
                // Only allow ESC when typing or when there's text/response visible
                const hasInput = searchInput.value.length > 0;
                const hasResponse = aiResponse.classList.contains('show') && aiResponse.innerHTML.trim().length > 0;
                
                if (!hasInput && !hasResponse) {
                    // On default page, ignore ESC
                    return;
                }
                
                logFrontend('ESC pressed', 'Starting hold timer');
                // Show ESC hint if not already visible
                escHint.classList.add('show');
                
                // Reset any previous animation state
                escLoading.classList.remove('active');
                const circle = escLoading.querySelector('circle');
                if (circle) {
                    // Reset circle to start position
                    circle.style.transition = 'none';
                    circle.style.strokeDashoffset = '50.27';
                    void circle.offsetWidth; // Force reflow to apply reset
                }
                
                escKeyDown = true;
                escHoldStartTime = Date.now();
                
                // Start animation after reset - ensure it's visible
                setTimeout(() => {
                    escHint.classList.add('show'); // Ensure hint is visible
                    escLoading.classList.add('active'); // Make loading visible first
                    if (circle) {
                        // Force reflow to ensure opacity change is applied
                        void escLoading.offsetWidth;
                        // Reset to start position
                        circle.style.transition = 'none';
                        circle.style.strokeDashoffset = '50.27';
                        void circle.offsetWidth; // Force reflow
                        // Now start the animation
                        circle.style.transition = 'stroke-dashoffset 1s linear';
                        circle.style.strokeDashoffset = '0'; // Animate to 0
                    }
                }, 10);
                
                escHoldTimer = setTimeout(() => {
                    // Only return to center if there's no conversation history
                    // Always return to main screen when ESC is held, regardless of chat history
                    logFrontend('ESC held', 'Returning to main screen');
                    // Reset everything
                    searchInput.value = '';
                    searchInput.blur();
                    returnToCenter();
                    escHint.classList.remove('show');
                    escLoading.classList.remove('active');
                    lastValue = '';
                    escKeyDown = false;
                    
                    // Hide buttons
                    addButton?.classList.remove('show');
                    moreOptionsButton.classList.remove('show');
                    searchInput.style.width = '100%';
                    
                    // Clear conversation history and AI response
                    conversationHistory = [];
                    aiResponse.classList.remove('show');
                    aiResponse.innerHTML = '';
                    // Add button doesn't need generating state
                    sendButtonInner.classList.remove('generating');
                    typingAudio.pause();
                    typingAudio.currentTime = 0;
                    clearOSINT();
                    
                    // Hide new chat button
                    if (newChatButton) {
                        newChatButton.classList.remove('show');
                    }
                    
                    // Update example prompts visibility
                    updateExamplePrompts();
                    // Reset circle for next time
                    const resetCircle = escLoading.querySelector('circle');
                    if (resetCircle) {
                        resetCircle.style.transition = 'none';
                        resetCircle.style.strokeDashoffset = '50.27';
                        void resetCircle.offsetWidth;
                        resetCircle.style.transition = 'stroke-dashoffset 1s linear';
                    }
                }, ESC_HOLD_TIME);
            }
        });

        document.addEventListener('keyup', (e) => {
            if (e.key === 'Escape' && escKeyDown) {
                logFrontend('ESC released', 'Hold timer cancelled');
                const holdDuration = Date.now() - escHoldStartTime;
                
                // Only allow release if held for minimum time
                if (holdDuration < ESC_MIN_HOLD) {
                    // Reset everything immediately for quick releases
                    escKeyDown = false;
                    if (escHoldTimer) {
                        clearTimeout(escHoldTimer);
                        escHoldTimer = null;
                    }
                    escLoading.classList.remove('active');
                    // Force complete reset of animation
                    const circle = escLoading.querySelector('circle');
                    if (circle) {
                        circle.style.transition = 'none';
                        circle.style.strokeDashoffset = '50.27';
                        void circle.offsetWidth; // Force reflow
                        circle.style.transition = '';
                    }
                    // Keep ESC hint visible - don't hide it until hold is completed
                    return;
                }
                
                escKeyDown = false;
                if (escHoldTimer) {
                    clearTimeout(escHoldTimer);
                    escHoldTimer = null;
                }
                // Completely reset animation
                escLoading.classList.remove('active');
                const circle = escLoading.querySelector('circle');
                if (circle) {
                    // Reset the circle animation completely
                    circle.style.transition = 'none';
                    circle.style.strokeDashoffset = '50.27';
                    void circle.offsetWidth; // Force reflow
                    circle.style.transition = 'stroke-dashoffset 1s linear';
                }
                // Keep ESC hint visible - don't hide it until hold is completed
            }
        });

        // Both send buttons use the same handler
        function handleSendClick(e) {
            e.preventDefault();
            e.stopPropagation();
            
            // If generating, cancel the request and animation (but keep the conversation)
            if (isGenerating) {
                logFrontend('Cancel clicked', 'Stopping generation');
                // Cancel fetch request if it exists
                if (currentAbortController) {
                    currentAbortController.abort();
                }
                // Cancel animation
                animationTimeouts.forEach(timeout => clearTimeout(timeout));
                animationTimeouts = [];
                isGenerating = false;
                // Add button doesn't need generating state
                sendButtonInner.classList.remove('generating');
                typingAudio.pause();
                typingAudio.currentTime = 0;
                // Don't clear the response - just stop the animation
                isProcessing = false;
                searchInput.disabled = false;
                // Add button doesn't need to be disabled
                sendButtonInner.disabled = false;
                sendButtonInner.disabled = false;
                currentAbortController = null;
                return;
            }
            
            // Get the current input value
            const message = searchInput.value.trim();
            if (message && !isProcessing) {
                sendMessage();
            }
        }
        
        // Inner send button handles sending
        sendButtonInner.addEventListener('click', handleSendClick);
        
        // New Chat button functionality
        function newChat() {
            logFrontend('New chat', 'Clearing conversation');
            // Clear conversation history
            conversationHistory = [];
            // Reset prompts so they refresh next time
            promptsCurrentlyShown = false;
            // Clear AI response
            aiResponse.classList.remove('show');
            aiResponse.innerHTML = '';
            // Add button doesn't need generating state
            sendButtonInner.classList.remove('generating');
            // Hide new chat button
            if (newChatButton) {
                newChatButton.classList.remove('show');
            }
            // Clear input
            searchInput.value = '';
            lastValue = '';
            // Stop any ongoing generation
            if (currentAbortController) {
                currentAbortController.abort();
            }
            animationTimeouts.forEach(timeout => clearTimeout(timeout));
            animationTimeouts = [];
            isGenerating = false;
            isProcessing = false;
            typingAudio.pause();
            typingAudio.currentTime = 0;
            // Return to center
            returnToCenter();
            searchInputWrapper.classList.remove('typing');
            escHint.classList.remove('show');
            addButton?.classList.remove('show');
            moreOptionsButton.classList.remove('show');
            searchInput.style.width = '100%';
            clearOSINT();
            // Scroll to top
            window.scrollTo({ top: 0, behavior: 'smooth' });
            
            // Update example prompts visibility
            updateExamplePrompts();
        }
        
        // Add click handler for new chat button
        if (newChatButton) {
            newChatButton.addEventListener('click', newChat);
        }
        
        // More Options Dropdown Functionality
        const moreOptionsDropdown = document.getElementById('moreOptionsDropdown');
        const summarizeChatBtn = document.getElementById('summarizeChat');
        const exportAsTextBtn = document.getElementById('exportAsText');
        const exportAsMarkdownBtn = document.getElementById('exportAsMarkdown');
        const exportAsPdfBtn = document.getElementById('exportAsPdf');
        
        // Keep dropdown open on hover
        let dropdownTimeout;
        moreOptionsButton.addEventListener('mouseenter', () => {
            clearTimeout(dropdownTimeout);
            moreOptionsDropdown.classList.add('show');
        });
        
        moreOptionsButton.addEventListener('mouseleave', () => {
            dropdownTimeout = setTimeout(() => {
                moreOptionsDropdown.classList.remove('show');
            }, 200);
        });
        
        moreOptionsDropdown.addEventListener('mouseenter', () => {
            clearTimeout(dropdownTimeout);
        });
        
        moreOptionsDropdown.addEventListener('mouseleave', () => {
            moreOptionsDropdown.classList.remove('show');
        });
        
        // Summarize Chat
        async function summarizeConversation() {
            if (conversationHistory.length === 0) {
                alert('No conversation to summarize.');
                return;
            }
            
            logFrontend('Summarize chat', `Messages: ${conversationHistory.length}`);
            
            // Build conversation text
            const conversationText = conversationHistory.map(msg => {
                return `User: ${msg.user}\nAI: ${msg.ai || '(No response yet)'}`;
            }).join('\n\n');
            
            try {
                const data = await requestSummary(conversationText);
                const summary = data.summary || data.response || 'Summary unavailable.';
                
                // Show summary in a nice way
                const summaryText = `📝 Conversation Summary:\n\n${summary}`;
                navigator.clipboard.writeText(summary).then(() => {
                    alert(summaryText + '\n\n(Copied to clipboard)');
                }).catch(() => {
                    alert(summaryText);
                });
                
                logFrontend('Summary generated', `Length: ${summary.length}`);
            } catch (error) {
                console.error('Error summarizing:', error);
                alert('Error: Could not generate summary. Make sure the Node server is running (start.bat or npm start).');
            }
        }
        
        // Export as Text
        function exportAsText() {
            if (conversationHistory.length === 0) {
                alert('No conversation to export.');
                return;
            }
            
            const text = conversationHistory.map((msg, index) => {
                let output = `Message ${index + 1}:\n`;
                output += `You: ${msg.user}\n`;
                if (msg.ai) {
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = msg.ai;
                    const plainText = tempDiv.textContent || tempDiv.innerText || msg.ai;
                    output += `AI: ${plainText}\n`;
                }
                return output;
            }).join('\n---\n\n');
            
            const blob = new Blob([text], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `chat-export-${new Date().toISOString().split('T')[0]}.txt`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            logFrontend('Exported as text', `Messages: ${conversationHistory.length}`);
        }
        
        // Export as Markdown
        function exportAsMarkdown() {
            if (conversationHistory.length === 0) {
                alert('No conversation to export.');
                return;
            }
            
            let markdown = `# Chat Export\n\n`;
            markdown += `*Exported on ${new Date().toLocaleString()}*\n\n`;
            markdown += `---\n\n`;
            
            conversationHistory.forEach((msg, index) => {
                markdown += `## Message ${index + 1}\n\n`;
                markdown += `### You\n\n${msg.user}\n\n`;
                if (msg.ai) {
                    markdown += `### AI\n\n`;
                    // Convert HTML to markdown (basic conversion)
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = msg.ai;
                    let aiText = tempDiv.textContent || tempDiv.innerText || msg.ai;
                    // Preserve some markdown-like formatting
                    aiText = aiText.replace(/\n\n/g, '\n\n');
                    markdown += `${aiText}\n\n`;
                }
                markdown += `---\n\n`;
            });
            
            const blob = new Blob([markdown], { type: 'text/markdown' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `chat-export-${new Date().toISOString().split('T')[0]}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            logFrontend('Exported as markdown', `Messages: ${conversationHistory.length}`);
        }
        
        // Export as PDF
        function exportAsPdf() {
            if (conversationHistory.length === 0) {
                alert('No conversation to export.');
                return;
            }

            // Build the export document with the DOM so document end-tags
            // never appear as raw markup inside this page's inline script.
            const exportDoc = document.implementation.createHTMLDocument('Chat Export');
            const style = exportDoc.createElement('style');
            style.textContent = [
                'body { font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; max-width: 800px; margin: 0 auto; padding: 40px 20px; line-height: 1.6; color: #333; }',
                '.message { margin-bottom: 20px; }',
                '.message-user { text-align: right; }',
                '.message-user-content { display: inline-block; background: #f0f0f0; padding: 10px 15px; border-radius: 12px 12px 2px 12px; max-width: 70%; }',
                '.message-ai-content { display: inline-block; background: #e8e8e8; padding: 10px 15px; border-radius: 2px 12px 12px 12px; max-width: 80%; }',
                '.message-label { font-size: 11px; color: #666; margin-bottom: 4px; text-transform: uppercase; }',
                'h1 { font-size: 24px; margin-bottom: 30px; }',
                'h2 { font-size: 20px; margin-top: 20px; }',
                'h3 { font-size: 16px; margin-top: 15px; }',
                'code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }',
                'pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }',
                'table { border-collapse: collapse; width: 100%; margin: 15px 0; }',
                'th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }',
                'th { background: #f0f0f0; }'
            ].join('\n');
            exportDoc.head.appendChild(style);

            const heading = exportDoc.createElement('h1');
            heading.textContent = 'Chat Export';
            exportDoc.body.appendChild(heading);

            const exportedOn = exportDoc.createElement('p');
            exportedOn.textContent = 'Exported on ' + new Date().toLocaleString();
            exportDoc.body.appendChild(exportedOn);

            conversationHistory.forEach((msg) => {
                const userBlock = exportDoc.createElement('div');
                userBlock.className = 'message message-user';

                const userLabel = exportDoc.createElement('div');
                userLabel.className = 'message-label';
                userLabel.textContent = 'Me';

                const userContent = exportDoc.createElement('div');
                userContent.className = 'message-user-content';
                userContent.textContent = msg.user;
                userContent.innerHTML = userContent.innerHTML.replace(/\n/g, '<br>');

                userBlock.appendChild(userLabel);
                userBlock.appendChild(userContent);
                exportDoc.body.appendChild(userBlock);

                if (msg.ai) {
                    const aiBlock = exportDoc.createElement('div');
                    aiBlock.className = 'message message-ai';

                    const aiLabel = exportDoc.createElement('div');
                    aiLabel.className = 'message-label';
                    aiLabel.textContent = 'AI';

                    const aiContent = exportDoc.createElement('div');
                    aiContent.className = 'message-ai-content';
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = msg.ai;
                    aiContent.innerHTML = tempDiv.innerHTML;

                    aiBlock.appendChild(aiLabel);
                    aiBlock.appendChild(aiContent);
                    exportDoc.body.appendChild(aiBlock);
                }
            });

            const htmlContent = '<!DOCTYPE html>\n' + exportDoc.documentElement.outerHTML;
            
            // Create blob and download
            const blob = new Blob([htmlContent], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `chat-export-${new Date().toISOString().split('T')[0]}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            // Note: For actual PDF generation, you would need a library like jsPDF or html2pdf
            // This exports as HTML which can be converted to PDF by the browser
            alert('Chat exported as HTML. Open it in your browser and use "Print to PDF" to save as PDF.');
            logFrontend('Exported as PDF (HTML)', `Messages: ${conversationHistory.length}`);
        }
        
        // Add event listeners
        if (summarizeChatBtn) {
            summarizeChatBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                summarizeConversation();
                moreOptionsDropdown.classList.remove('show');
            });
        }
        
        if (exportAsTextBtn) {
            exportAsTextBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportAsText();
                moreOptionsDropdown.classList.remove('show');
            });
        }
        
        if (exportAsMarkdownBtn) {
            exportAsMarkdownBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportAsMarkdown();
                moreOptionsDropdown.classList.remove('show');
            });
        }
        
        if (exportAsPdfBtn) {
            exportAsPdfBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                exportAsPdf();
                moreOptionsDropdown.classList.remove('show');
            });
        }
        
        // Add Options Dropdown Menu Item Handlers
        const uploadFileBtn = document.getElementById('uploadFile');
        const uploadImageBtn = document.getElementById('uploadImage');
        const uploadPDFBtn = document.getElementById('uploadPDF');
        const uploadDocumentBtn = document.getElementById('uploadDocument');
        const deepSearchBtn = document.getElementById('deepSearch');
        const scanQRBtn = document.getElementById('scanQR');
        
        // Upload File handler
        if (uploadFileBtn) {
            uploadFileBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.accept = '*/*';
                input.onchange = (event) => {
                    const files = event.target.files;
                    if (files.length > 0) {
                        // TODO: Implement file upload functionality
                        console.log('Files selected:', files);
                        // You can add file upload logic here
                    }
                };
                input.click();
                if (addOptionsDropdown) {
                    addOptionsDropdown.classList.remove('show');
                }
            });
        }
        
        // Upload Image handler
        if (uploadImageBtn) {
            uploadImageBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.accept = 'image/*';
                input.onchange = (event) => {
                    const files = event.target.files;
                    if (files.length > 0) {
                        // TODO: Implement image upload functionality
                        console.log('Images selected:', files);
                        // You can add image upload logic here
                    }
                };
                input.click();
                if (addOptionsDropdown) {
                    addOptionsDropdown.classList.remove('show');
                }
            });
        }
        
        // Upload PDF handler
        if (uploadPDFBtn) {
            uploadPDFBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.accept = 'application/pdf';
                input.onchange = (event) => {
                    const files = event.target.files;
                    if (files.length > 0) {
                        // TODO: Implement PDF upload functionality
                        console.log('PDFs selected:', files);
                        // You can add PDF upload logic here
                    }
                };
                input.click();
                if (addOptionsDropdown) {
                    addOptionsDropdown.classList.remove('show');
                }
            });
        }
        
        // Upload Document handler
        if (uploadDocumentBtn) {
            uploadDocumentBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.accept = '.doc,.docx,.txt,.rtf';
                input.onchange = (event) => {
                    const files = event.target.files;
                    if (files.length > 0) {
                        // TODO: Implement document upload functionality
                        console.log('Documents selected:', files);
                        // You can add document upload logic here
                    }
                };
                input.click();
                if (addOptionsDropdown) {
                    addOptionsDropdown.classList.remove('show');
                }
            });
        }
        
        // Deep Search handler
        if (deepSearchBtn) {
            deepSearchBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                // TODO: Implement deep search functionality
                console.log('Deep search clicked');
                // You can add deep search logic here
                if (addOptionsDropdown) {
                    addOptionsDropdown.classList.remove('show');
                }
            });
        }
        
        // Scan QR Code handler
        if (scanQRBtn) {
            scanQRBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                // TODO: Implement QR code scanning functionality
                console.log('Scan QR code clicked');
                // You can add QR code scanning logic here
                if (addOptionsDropdown) {
                    addOptionsDropdown.classList.remove('show');
                }
            });
        }
        
        // Disable items when no conversation history
        function updateMoreOptionsMenu() {
            const hasHistory = conversationHistory.length > 0;
            [summarizeChatBtn, exportAsTextBtn, exportAsMarkdownBtn, exportAsPdfBtn].forEach(btn => {
                if (btn) {
                    if (hasHistory) {
                        btn.classList.remove('disabled');
                    } else {
                        btn.classList.add('disabled');
                    }
                }
            });
        }
        
        // Update menu state when conversation changes
        const originalRenderConversation = renderConversation;
        renderConversation = function() {
            originalRenderConversation();
            updateMoreOptionsMenu();
        };
        
        updateMoreOptionsMenu();

        const searchInputWrapper = document.querySelector('.search-input-wrapper');
        searchInput.addEventListener('focus', () => {
            logFrontend('Input focused');
            searchInputWrapper.classList.add('focused');
            updateExamplePrompts();
        });

        searchInput.addEventListener('blur', () => {
            logFrontend('Input blurred');
            searchInputWrapper.classList.remove('focused');
            // Delay hiding to allow clicks on example prompts
            setTimeout(() => {
                if (document.activeElement !== searchInput) {
                    updateExamplePrompts();
                }
            }, 200);
        });

        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !isProcessing) {
                // Always trigger explosion if there are letters on screen
                if (fallingLetters.length > 0) {
                    triggerExplosion();
                }
                sendMessage();
            }
        });

        searchInput.focus();
        
        // Update ground position on window resize
        window.addEventListener('resize', () => {
            // Ground position will be recalculated in getGroundY()
        });
