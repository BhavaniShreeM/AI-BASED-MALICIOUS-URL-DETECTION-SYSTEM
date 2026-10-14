/**
 * AI-Based Malicious URL Detection System
 * Frontend Client Controller (Vanilla JavaScript)
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const urlForm = document.getElementById('urlForm');
  const urlInput = document.getElementById('urlInput');
  const clearBtn = document.getElementById('clearBtn');
  const scanBtn = document.getElementById('scanBtn');
  const btnText = scanBtn.querySelector('.btn-text');
  const btnSpinner = scanBtn.querySelector('.btn-spinner');
  
  const inputError = document.getElementById('inputError');
  const errorText = document.getElementById('errorText');
  const loadingState = document.getElementById('loadingState');
  const apiNotice = document.getElementById('apiNotice');
  const resultsSection = document.getElementById('resultsSection');
  
  const safeCard = document.getElementById('safeCard');
  const suspiciousCard = document.getElementById('suspiciousCard');
  const maliciousCard = document.getElementById('maliciousCard');
  const displayInspectedUrl = document.getElementById('displayInspectedUrl');
  const riskCountBadge = document.getElementById('riskCountBadge');
  const riskIndicatorsList = document.getElementById('riskIndicatorsList');
  const recommendationsList = document.getElementById('recommendationsList');
  
  const sampleChips = document.querySelectorAll('.sample-chip');
  const previewSafeBtn = document.getElementById('previewSafeBtn');
  const previewSuspiciousBtn = document.getElementById('previewSuspiciousBtn');
  const previewMaliciousBtn = document.getElementById('previewMaliciousBtn');

  // Input typing listener for clear button
  urlInput.addEventListener('input', () => {
    clearBtn.style.display = urlInput.value.trim() ? 'block' : 'none';
    hideError();
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    hideError();
    urlInput.focus();
  });

  // Sample Chips Click Handlers
  sampleChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      const url = chip.getAttribute('data-url');
      urlInput.value = url;
      clearBtn.style.display = 'block';
      hideError();
      executeScan(url);
    });
  });

  // State Preview Buttons (For testing all 3 cards before backend integration)
  if (previewSafeBtn) {
    previewSafeBtn.addEventListener('click', () => {
      renderSafeState(urlInput.value.trim() || 'https://www.google.com/search?q=cybersecurity');
    });
  }
  if (previewSuspiciousBtn) {
    previewSuspiciousBtn.addEventListener('click', () => {
      renderSuspiciousState(urlInput.value.trim() || 'http://bit.ly/3xY9PqL-security-notice');
    });
  }
  if (previewMaliciousBtn) {
    previewMaliciousBtn.addEventListener('click', () => {
      renderMaliciousState(urlInput.value.trim() || 'http://192.168.1.104/paypal.com/login.php');
    });
  }

  // Form Submit Handler
  urlForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const rawUrl = urlInput.value.trim();
    
    // Step 1: Validate input
    const validation = validateUrlFormat(rawUrl);
    if (!validation.isValid) {
      showError(validation.message);
      return;
    }
    
    hideError();
    executeScan(rawUrl);
  });

  /**
   * Client-side URL Format Validation
   */
  function validateUrlFormat(input) {
    if (!input) {
      return { isValid: false, message: 'URL field cannot be empty. Please enter a link to scan.' };
    }
    if (input.length < 3) {
      return { isValid: false, message: 'URL is too short to evaluate.' };
    }
    // Must contain dot (domain) or colon (port/protocol)
    if (!input.includes('.') && !input.includes(':')) {
      return {
        isValid: false,
        message: 'Invalid format: Must contain a valid domain (e.g. example.com) or an IP address.'
      };
    }
    return { isValid: true };
  }

  function showError(msg) {
    errorText.textContent = msg;
    inputError.style.display = 'flex';
  }

  function hideError() {
    inputError.style.display = 'none';
  }

  function setLoading(isLoading) {
    if (isLoading) {
      scanBtn.disabled = true;
      btnText.textContent = 'Scanning...';
      btnSpinner.style.display = 'inline-block';
      loadingState.style.display = 'flex';
      resultsSection.style.display = 'none';
      apiNotice.style.display = 'none';
    } else {
      scanBtn.disabled = false;
      btnText.textContent = 'Scan URL';
      btnSpinner.style.display = 'none';
      loadingState.style.display = 'none';
    }
  }

  /**
   * Main scan function: sends request to backend API
   */
  async function executeScan(url) {
    setLoading(true);

    try {
      // Send real POST request to backend API
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (response.status === 400) {
        const errData = await response.json().catch(() => ({}));
        setLoading(false);
        showError(errData.error || 'Invalid URL format. Please enter a valid website link.');
        return;
      }

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setLoading(false);
      apiNotice.style.display = 'none';
      renderBackendResults(data);

    } catch (err) {
      console.warn('Backend API connection note:', err.message);
      setLoading(false);
      
      // Show notice that backend API is not connected yet
      apiNotice.style.display = 'flex';
      
      // Perform client-side feature detection preview as fallback
      performClientSideFeaturePreview(url);
    }
  }

  /**
   * Renders real results returned from the backend API
   */
  function renderBackendResults(data) {
    resultsSection.style.display = 'flex';
    displayInspectedUrl.textContent = data.url;

    // Reset verdict cards
    safeCard.style.display = 'none';
    suspiciousCard.style.display = 'none';
    maliciousCard.style.display = 'none';

    if (data.verdict === 'MALICIOUS') {
      maliciousCard.style.display = 'block';
    } else if (data.verdict === 'SUSPICIOUS') {
      suspiciousCard.style.display = 'block';
    } else {
      safeCard.style.display = 'block';
    }

    renderIndicators(data.risk_factors || []);
    renderRecommendations(data.recommendations || []);
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  /**
   * Client-side preview feature extractor for testing before backend ML model is hooked up
   */
  function performClientSideFeaturePreview(url) {
    resultsSection.style.display = 'flex';
    displayInspectedUrl.textContent = url;

    const lower = url.toLowerCase();
    const hasIp = /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}/.test(url);
    const hasAt = url.includes('@');
    const isShort = /bit\.ly|tinyurl|t\.co|goo\.gl/.test(lower);
    const hasKeywords = /login|verify|account|banking|paypal|update|security/.test(lower);
    const hasSuspiciousTld = /\.xyz|\.top|\.tk|\.buzz|\.ml/.test(lower);

    if (hasIp || hasAt || (hasKeywords && hasSuspiciousTld)) {
      renderMaliciousState(url);
    } else if (isShort || hasSuspiciousTld || hasKeywords) {
      renderSuspiciousState(url);
    } else {
      renderSafeState(url);
    }
  }

  function renderSafeState(url) {
    resultsSection.style.display = 'flex';
    displayInspectedUrl.textContent = url;
    safeCard.style.display = 'block';
    suspiciousCard.style.display = 'none';
    maliciousCard.style.display = 'none';

    const indicators = [
      {
        title: 'Domain Structure',
        value: 'Standard Top-Level Domain',
        status: 'clean',
        pill: 'Clean',
        desc: 'URL uses legitimate domain registration conventions with verified hierarchy.'
      },
      {
        title: 'Credential Routing',
        value: 'No "@" symbol detected',
        status: 'clean',
        pill: 'Clean',
        desc: 'Direct routing without browser userinfo credential redirection.'
      },
      {
        title: 'Host Identity',
        value: 'Registered DNS Hostname',
        status: 'clean',
        pill: 'Clean',
        desc: 'Identified via public DNS rather than an anonymous raw IP address.'
      }
    ];

    const recommendations = [
      'This URL displays standard, non-malicious lexical patterns.',
      'Always verify that the website domain name corresponds to your intended service.',
      'Remember that URL analysis assesses link structure; always exercise caution before sharing credentials on unfamiliar forms.'
    ];

    renderIndicators(indicators);
    renderRecommendations(recommendations);
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  function renderSuspiciousState(url) {
    resultsSection.style.display = 'flex';
    displayInspectedUrl.textContent = url;
    safeCard.style.display = 'none';
    suspiciousCard.style.display = 'block';
    maliciousCard.style.display = 'none';

    const indicators = [
      {
        title: 'Destination Obfuscation',
        value: 'Redirect or Shortener Pattern',
        status: 'warning',
        pill: 'Warning',
        desc: 'The real destination domain is masked, preventing preview inspection.'
      },
      {
        title: 'Keyword Density',
        value: 'Suspicious Security Terminology',
        status: 'warning',
        pill: 'Attention',
        desc: 'Keywords like "verify", "account", or "update" appear in the URL.'
      },
      {
        title: 'Domain Extension',
        value: 'High-Abuse TLD or Deep Subdomains',
        status: 'warning',
        pill: 'Caution',
        desc: 'The domain uses an extension frequently associated with disposable spam.'
      }
    ];

    const recommendations = [
      'Exercise caution: Do not enter login passwords or payment details on this site.',
      'Expand shortened links with a link-unshortener before visiting.',
      'Check the browser address bar carefully for typosquatting variations of known brands.',
      'Note: HTTPS (the padlock) only encrypts transit; it does not verify the website is trustworthy.'
    ];

    renderIndicators(indicators);
    renderRecommendations(recommendations);
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  function renderMaliciousState(url) {
    resultsSection.style.display = 'flex';
    displayInspectedUrl.textContent = url;
    safeCard.style.display = 'none';
    suspiciousCard.style.display = 'none';
    maliciousCard.style.display = 'block';

    const indicators = [
      {
        title: 'Critical Host Anomaly',
        value: 'Raw Numerical IP Address',
        status: 'critical',
        pill: 'High Risk',
        desc: 'Hosting directly on an IP address bypasses legitimate domain identity registration.'
      },
      {
        title: 'Credential Confusion (@)',
        value: 'Embedded "@" Character',
        status: 'critical',
        pill: 'Exploit Token',
        desc: 'Browsers ignore characters before the "@", tricking users into visiting an attacker domain.'
      },
      {
        title: 'Deceptive Brand Mimicry',
        value: 'Spoofed Financial Keywords',
        status: 'critical',
        pill: 'Phishing',
        desc: 'Targets banking or digital wallet credentials via fraudulent paths.'
      }
    ];

    const recommendations = [
      'DO NOT visit or open this link. It presents high-confidence indicators of malware or phishing.',
      'Never input credentials, bank information, or one-time security codes.',
      'If sent by an acquaintance, their account may be compromised; notify them via a separate channel.',
      'Report the link to your security team or anti-phishing clearinghouses (e.g., Google Safe Browsing).'
    ];

    renderIndicators(indicators);
    renderRecommendations(recommendations);
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  function renderIndicators(items) {
    riskCountBadge.textContent = `${items.length} Indicators`;
    riskIndicatorsList.innerHTML = '';

    items.forEach((rawItem) => {
      const item = typeof rawItem === 'string'
        ? {
            title: 'Threat Indicator',
            value: rawItem,
            status: 'warning',
            pill: 'Detected',
            desc: rawItem
          }
        : rawItem;

      const card = document.createElement('div');
      card.className = `indicator-card ${item.status || ''}`;
      
      const pillClass = item.status === 'critical' ? 'danger' : item.status === 'warning' ? 'warning' : 'clean';
      
      card.innerHTML = `
        <div class="indicator-header">
          <span class="indicator-title">${escapeHtml(item.title || 'Risk Indicator')}</span>
          <span class="indicator-pill ${pillClass}">${escapeHtml(item.pill || item.status || 'Alert')}</span>
        </div>
        <div class="indicator-value">${escapeHtml(item.value || '')}</div>
        <div class="indicator-desc">${escapeHtml(item.desc || item.description || '')}</div>
      `;
      riskIndicatorsList.appendChild(card);
    });
  }

  function renderRecommendations(items) {
    recommendationsList.innerHTML = '';
    items.forEach((rec, idx) => {
      const div = document.createElement('div');
      div.className = 'rec-item';
      div.innerHTML = `
        <span class="rec-number">${idx + 1}</span>
        <span>${escapeHtml(rec)}</span>
      `;
      recommendationsList.appendChild(div);
    });
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
});
