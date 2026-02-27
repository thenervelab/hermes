document.addEventListener('DOMContentLoaded', () => {

    // Mobile Menu Toggle
    const mobileMenu = document.getElementById('mobile-menu');
    const navLinks = document.querySelector('.nav-links');

    if (mobileMenu && navLinks) {
        mobileMenu.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            const icon = mobileMenu.querySelector('i');
            if (navLinks.classList.contains('active')) {
                icon.classList.remove('bx-menu');
                icon.classList.add('bx-x');
            } else {
                icon.classList.remove('bx-x');
                icon.classList.add('bx-menu');
            }
        });
    }

    // Docs Sidebar Toggle
    const sidebarToggle = document.getElementById('docs-sidebar-toggle');
    const docsNav = document.querySelector('.docs-nav');

    if (sidebarToggle && docsNav) {
        sidebarToggle.addEventListener('click', () => {
            docsNav.classList.toggle('expanded');
            const icon = sidebarToggle.querySelector('i');
            if (docsNav.classList.contains('expanded')) {
                icon.classList.remove('bx-menu');
                icon.classList.add('bx-x');
            } else {
                icon.classList.remove('bx-x');
                icon.classList.add('bx-menu');
            }
        });
    }

    // Smooth copy-to-clipboard functionality
    const copySnippet = document.getElementById('copy-snippet');
    if (copySnippet) {
        copySnippet.addEventListener('click', () => {
            const codeToCopy = "pip install hippius-hermes";

            navigator.clipboard.writeText(codeToCopy).then(() => {
                const icon = copySnippet.querySelector('.copy-icon');

                // Visual feedback cycle
                icon.classList.remove('bx-copy');
                icon.classList.add('bx-check');
                icon.style.color = 'var(--accent-blue)';

                setTimeout(() => {
                    icon.classList.remove('bx-check');
                    icon.classList.add('bx-copy');
                    icon.style.color = 'var(--text-muted)';
                }, 2000);
            });
        });
    }

    // Intersection Observer for scroll animations (Soft Slide-up Reveal)
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.15
    };

    const observer = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                // Optional: unobserve if you only want it to fire once
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    const animatedElements = document.querySelectorAll('.reveal-on-scroll');

    animatedElements.forEach(el => {
        observer.observe(el);
    });

    // Mac Code Editor Interactive Logic
    const codeSnippets = {
        'subnet_integration.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    <span class="comment"># Load config with subnet whitelisting</span>\n    config = Config(\n        node_secret_key_path=<span class="string">"/etc/hermes/iroh.key"</span>,\n        ss58_address=<span class="string">"5GrwvaEF5zXb26Fz9rcQpDW..."</span>,\n        api_token=<span class="string">"sk-your-token"</span>,\n        storage_directory=<span class="string">".hermes_data"</span>,\n        subnet_ids=[<span class="function">42</span>, <span class="function">69</span>]  <span class="comment"># Accept traffic from subnets 42 &amp; 69</span>\n    )\n    client = <span class="keyword">await</span> HermesClient.create(config)\n\n    <span class="comment"># Send model weights directly via P2P QUIC</span>\n    filename = <span class="keyword">await</span> client.send_file_unencrypted(\n        <span class="string">"5FHneW46xGXgs5mUiveU4sbTy..."</span>,\n        <span class="string">"./model_weights.safetensors"</span>\n    )\n    <span class="function">print</span>(<span class="string">f"Sent! File: {filename}"</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`,
        'hermes_config.json': `<span class="keyword">{</span>\n  <span class="string">"node_secret_key_path"</span><span class="keyword">:</span> <span class="string">"/etc/hermes/iroh.key"</span><span class="keyword">,</span>\n  <span class="string">"ss58_address"</span><span class="keyword">:</span> <span class="string">"5GrwvaEF5zXb26Fz9rcQpDW..."</span><span class="keyword">,</span>\n  <span class="string">"api_token"</span><span class="keyword">:</span> <span class="string">"sk-live-..."</span><span class="keyword">,</span>\n  <span class="string">"storage_directory"</span><span class="keyword">:</span> <span class="string">"/var/hermes"</span><span class="keyword">,</span>\n  <span class="string">"subnet_ids"</span><span class="keyword">:</span> <span class="keyword">[</span><span class="function">42</span><span class="keyword">,</span> <span class="function">69</span><span class="keyword">]</span><span class="keyword">,</span>\n  <span class="string">"s3"</span><span class="keyword">:</span> <span class="keyword">{</span>\n    <span class="string">"bucket"</span><span class="keyword">:</span> <span class="string">"hippius-arion"</span><span class="keyword">,</span>\n    <span class="string">"access_key"</span><span class="keyword">:</span> <span class="string">"YOUR_KEY"</span><span class="keyword">,</span>\n    <span class="string">"secret_key"</span><span class="keyword">:</span> <span class="string">"YOUR_SECRET"</span>\n  <span class="keyword">}</span><span class="keyword">,</span>\n  <span class="string">"enable_firewall"</span><span class="keyword">:</span> <span class="keyword">true</span>\n<span class="keyword">}</span>`,
        'send_payload.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    <span class="comment"># Setup client from config file</span>\n    config = Config.from_file(<span class="string">"hermes_config.json"</span>)\n    client = <span class="keyword">await</span> HermesClient.create(config)\n    \n    <span class="comment"># Send file directly to peer via P2P QUIC</span>\n    filename = <span class="keyword">await</span> client.send_file_unencrypted(\n        <span class="string">"5GrwvaEF5zXb26Fz9rcQpDW..."</span>,\n        <span class="string">"./weights.safetensors"</span>\n    )\n    <span class="function">print</span>(<span class="string">f"Sent! File: {filename}"</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`,
        'receive_payload.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">def</span> <span class="function">on_message</span>(action, sender_ss58, payload):\n    <span class="function">print</span>(<span class="string">f"Incoming from {sender_ss58}"</span>)\n    <span class="function">print</span>(<span class="string">f"Action: {action}, Size: {len(payload)} bytes"</span>)\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    config = Config.from_file(<span class="string">"hermes_config.json"</span>)\n    client = <span class="keyword">await</span> HermesClient.create(config)\n    \n    <span class="comment"># Start QUIC listener with ALPN filtering</span>\n    client.start_listener(on_message)\n    <span class="function">print</span>(<span class="string">"Listening for Hermes messages..."</span>)\n    \n    <span class="keyword">while</span> <span class="keyword">True</span>:\n        <span class="keyword">await</span> asyncio.sleep(<span class="function">3600</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`,
        'send_direct.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    config = Config.from_file(<span class="string">"hermes_config.json"</span>)\n    client = <span class="keyword">await</span> HermesClient.create(config)\n\n    <span class="comment"># Direct P2P: stream file over QUIC, no intermediary</span>\n    filename = <span class="keyword">await</span> client.send_file_unencrypted(\n        <span class="string">"5FHneW46xGXgs5mUiveU4sbTy..."</span>,\n        <span class="string">"./gradients.safetensors"</span>\n    )\n    <span class="function">print</span>(<span class="string">f"Sent directly! File: {filename}"</span>)\n\n    <span class="comment"># Or use S3 for massive payloads with pre-signed URLs</span>\n    <span class="keyword">await</span> client.send_file_via_s3(\n        <span class="string">"5FHneW46xGXgs5mUiveU4sbTy..."</span>,\n        <span class="string">"./model_weights.safetensors"</span>\n    )\n    <span class="function">print</span>(<span class="string">"S3 payload shared!"</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`,
        'send_s3.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    config = Config.from_file(<span class="string">"hermes_config.json"</span>)\n    client = <span class="keyword">await</span> HermesClient.create(config)\n\n    <span class="comment"># Auto-upload to S3, Pre-Sign URL, &amp; transmit securely</span>\n    <span class="keyword">await</span> client.send_file_via_s3(\n        <span class="string">"5FHneW46xGXgs5mUiveU4sbTy..."</span>,\n        <span class="string">"./massive_tensor.safetensors"</span>\n    )\n    <span class="function">print</span>(<span class="string">"S3 Payload Shared!"</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`,
        'receive_direct.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    config = Config.from_file(<span class="string">"hermes_config.json"</span>)\n    client = <span class="keyword">await</span> HermesClient.create(config)\n\n    <span class="keyword">def</span> <span class="function">on_message</span>(action, sender_ss58, payload):\n        <span class="function">print</span>(<span class="string">f"Control: {action} from {sender_ss58}"</span>)\n\n    <span class="keyword">def</span> <span class="function">on_file</span>(sender_ss58, filename, local_path, file_size):\n        size_mb = file_size / (<span class="function">1024</span> * <span class="function">1024</span>)\n        <span class="function">print</span>(<span class="string">f"Received {filename} ({size_mb:.2f} MB)"</span>)\n        <span class="function">print</span>(<span class="string">f"  From:     {sender_ss58}"</span>)\n        <span class="function">print</span>(<span class="string">f"  Saved to: {local_path}"</span>)\n\n    <span class="comment"># Listen for both control messages and direct P2P files</span>\n    client.start_listener(on_message, on_data=on_file)\n\n    <span class="function">print</span>(<span class="string">"Waiting for incoming P2P files..."</span>)\n    <span class="keyword">while</span> <span class="keyword">True</span>:\n        <span class="keyword">await</span> asyncio.sleep(<span class="function">3600</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`,
        'e2e_encryption.py': `<span class="keyword">import</span> asyncio\n<span class="keyword">from</span> hermes <span class="keyword">import</span> Config, HermesClient\n\n<span class="keyword">async def</span> <span class="function">main</span>():\n    config = Config.from_file(<span class="string">"hermes_config.json"</span>)\n    client = <span class="keyword">await</span> HermesClient.create(config)\n\n    <span class="comment"># Hermes natively automates the blockchain identity resolution</span>\n    <span class="comment"># and NaCl SealedBox encryption (X25519 + XSalsa20-Poly1305).</span>\n    <span class="keyword">await</span> client.send_message_encrypted(\n        <span class="string">"5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"</span>,\n        <span class="string">"encrypted_message"</span>,\n        <span class="string">b"top secret payload data"</span>\n    )\n    <span class="function">print</span>(<span class="string">"Payload securely encrypted and delivered!"</span>)\n\n<span class="keyword">if</span> __name__ == <span class="string">"__main__"</span>:\n    asyncio.run(main())`
    };

    const macWindows = document.querySelectorAll('.mac-window');

    macWindows.forEach(macWindow => {
        const macFiles = macWindow.querySelectorAll('.mac-files li');
        const editorHeader = macWindow.querySelector('.editor-header span');
        const editorCode = macWindow.querySelector('.editor-inner pre code');

        if (macFiles.length > 0 && editorHeader && editorCode) {
            macFiles.forEach(fileEl => {
                fileEl.addEventListener('click', () => {
                    // Remove active class from all tabs in this window
                    macFiles.forEach(el => el.classList.remove('active'));

                    // Add active class to the clicked tab
                    fileEl.classList.add('active');

                    // Get filename
                    const fileName = fileEl.textContent.trim();

                    // Only update if we have a snippet
                    if (codeSnippets[fileName]) {
                        editorHeader.textContent = fileName;

                        // Smooth transition
                        editorCode.style.opacity = '0';
                        setTimeout(() => {
                            editorCode.innerHTML = codeSnippets[fileName];
                            editorCode.style.opacity = '1';
                        }, 200);
                    }
                });
            });
        }
    });
});
