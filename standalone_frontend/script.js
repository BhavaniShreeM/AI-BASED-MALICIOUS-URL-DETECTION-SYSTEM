/**
 * AI-Based Malicious URL Detection System
 * Frontend Client Controller (Vanilla JavaScript)
 * Communicates with the Python Flask Backend API (/api/scan)
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

  // Sample Chips Click Handlers:
  // Rule: Sample URL buttons must ONLY fill the input field; they must NOT generate fake results.
  sampleChips.forEach((chip) => {
    chip.addEventListener('click', () => {
      const url = chip.getAttribute('data-url');
      urlInput.value = url;
      clearBtn.style.display = 'block';
      hideError();
      urlInput.focus();
    });
  });

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
    if (!input.includes('.') && !input.includes(':') && !input.toLowerCase().includes('localhost')) {
      return {
        isValid: false,
        message: 'Invalid format: Must contain a valid domain (e.g. example.com) or an IP address.'
      };
    }
    if (/\s/.test(input)) {
      return {
        isValid: false,
        message: 'Invalid format: URLs cannot contain spaces.'
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
      if (apiNotice) apiNotice.style.display = 'none';
    } else {
      scanBtn.disabled = false;
      btnText.textContent = 'Scan URL';
      btnSpinner.style.display = 'none';
      loadingState.style.display = 'none';
    }
  }

  /**
   * Main scan function: sends real request to Python Flask backend API
   */
  async function executeScan(url) {
    setLoading(true);

    try {
      // Primary scan endpoint with fallback to /api/analyze
      let response;
      try {
        response = await fetch('/api/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({ url }),
        });
      } catch (primaryErr) {
        // Fallback to /api/analyze if /api/scan is not directly reached
        response = await fetch('/api/analyze', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({ url }),
        });
      }

      if (response.status === 400) {
        const errData = await response.json().catch(() => ({}));
        setLoading(false);
        showError(errData.error || 'Invalid URL format. Please enter a valid website link.');
        return;
      }

      if (response.status === 503) {
        const errData = await response.json().catch(() => ({}));
        setLoading(false);
        showError(errData.error || 'Machine Learning model is not available. Please run train_model.py first.');
        return;
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.error || `Server returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setLoading(false);
      renderBackendResults(data);

    } catch (err) {
      console.error('Backend connection error:', err);
      setLoading(false);
      showError(`Backend connection failed: ${err.message}. Please check if the Flask server is running on port 5000.`);
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

    const category = (data.category || data.verdict || 'SAFE').toUpperCase();

    // Update tags with actual confidence score from Random Forest model
    const confScore = data.confidence_percentage !== undefined ? `${data.confidence_percentage}% Confidence` : 'Evaluated';
    const probText = data.malicious_probability !== undefined ? ` (Malicious Probability: ${(data.malicious_probability * 100).toFixed(1)}%)` : '';

    if (category === 'MALICIOUS') {
      maliciousCard.style.display = 'block';
      const tag = maliciousCard.querySelector('.confidence-tag');
      if (tag) tag.textContent = `${confScore}${probText}`;
      const summary = maliciousCard.querySelector('.verdict-summary');
      if (summary && data.explanation) summary.textContent = data.explanation;
    } else if (category === 'SUSPICIOUS') {
      suspiciousCard.style.display = 'block';
      const tag = suspiciousCard.querySelector('.confidence-tag');
      if (tag) tag.textContent = `${confScore}${probText}`;
      const summary = suspiciousCard.querySelector('.verdict-summary');
      if (summary && data.explanation) summary.textContent = data.explanation;
    } else {
      safeCard.style.display = 'block';
      const tag = safeCard.querySelector('.confidence-tag');
      if (tag) tag.textContent = `${confScore} (Legitimate Probability: ${(data.legitimate_probability * 100).toFixed(1)}%)`;
      const summary = safeCard.querySelector('.verdict-summary');
      if (summary && data.explanation) summary.textContent = data.explanation;
    }

    renderIndicators(data.risk_factors || [], category);
    renderRecommendations(data.recommendations || []);
    resultsSection.scrollIntoView({ behavior: 'smooth' });
  }

  function renderIndicators(items, category) {
    riskCountBadge.textContent = `${items.length} Factors`;
    riskIndicatorsList.innerHTML = '';

    items.forEach((rawItem) => {
      let title = 'Threat Factor';
      let value = '';
      let desc = '';
      let status = category === 'MALICIOUS' ? 'critical' : category === 'SUSPICIOUS' ? 'warning' : 'clean';
      let pill = category === 'MALICIOUS' ? 'Danger' : category === 'SUSPICIOUS' ? 'Warning' : 'Baseline';

      if (typeof rawItem === 'string') {
        value = rawItem;
        desc = rawItem;
        if (rawItem.includes('IPv4') || rawItem.includes('IP address')) {
          title = 'Direct Host IP';
          status = 'critical';
          pill = 'High Risk';
        } else if (rawItem.includes('@')) {
          title = 'Credential Spoofing (@)';
          status = 'critical';
          pill = 'Evasion';
        } else if (rawItem.includes('HTTPS')) {
          title = 'Unencrypted HTTP';
          status = 'warning';
          pill = 'No SSL';
        } else if (rawItem.includes('keyword')) {
          title = 'Sensitive Keyword Density';
          status = 'warning';
          pill = 'Phishing Pattern';
        } else if (rawItem.includes('subdomain')) {
          title = 'Subdomain Nesting';
          status = 'warning';
          pill = 'Anomalous';
        } else if (rawItem.includes('No typical malicious')) {
          title = 'Lexical Baseline';
          status = 'clean';
          pill = 'Standard';
        }
      } else if (typeof rawItem === 'object' && rawItem !== null) {
        title = rawItem.title || 'Threat Indicator';
        value = rawItem.value || '';
        desc = rawItem.desc || rawItem.description || '';
        status = rawItem.status || status;
        pill = rawItem.pill || pill;
      }

      const card = document.createElement('div');
      card.className = `indicator-card ${status}`;
      const pillClass = status === 'critical' ? 'danger' : status === 'warning' ? 'warning' : 'clean';

      card.innerHTML = `
        <div class="indicator-header">
          <span class="indicator-title">${escapeHtml(title)}</span>
          <span class="indicator-pill ${pillClass}">${escapeHtml(pill)}</span>
        </div>
        <div class="indicator-value">${escapeHtml(value)}</div>
        <div class="indicator-desc">${escapeHtml(desc)}</div>
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
