'use strict';

// confirm dialogs
document.addEventListener('submit', (e) => {
  const msg = e.target.getAttribute && e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});

// password + confirm match check (server also enforces this)
document.querySelectorAll('form[data-match-password]').forEach((form) => {
  const pw = form.querySelector('input[name="password"]');
  const confirm = form.querySelector('input[name="password_confirm"]');
  if (!pw || !confirm) return;
  const check = () => confirm.setCustomValidity(confirm.value && confirm.value !== pw.value ? 'Passwords do not match' : '');
  pw.addEventListener('input', check);
  confirm.addEventListener('input', check);
});

// click-to-copy record boxes
document.querySelectorAll('[data-copy]').forEach((el) => {
  el.title = 'Click to copy';
  el.style.cursor = 'pointer';
  el.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(el.textContent.trim());
      const prev = el.style.borderColor;
      el.style.borderColor = 'var(--accent)';
      setTimeout(() => { el.style.borderColor = prev; }, 600);
    } catch (_) { /* clipboard unavailable */ }
  });
});

// native <dialog> modals (help popups)
document.querySelectorAll('[data-modal-open]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const d = document.getElementById(btn.dataset.modalOpen);
    if (d && typeof d.showModal === 'function') d.showModal();
  });
});
document.querySelectorAll('[data-modal-close]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const d = btn.closest('dialog');
    if (d) d.close();
  });
});

// DNS provider form: show only the selected type's credential fields
const typeSelect = document.getElementById('dns-type');
if (typeSelect) {
  const update = () => {
    document.querySelectorAll('.dns-fields').forEach((div) => {
      div.style.display = div.dataset.type === typeSelect.value ? '' : 'none';
    });
  };
  typeSelect.addEventListener('change', update);
  update();
}

// certificate detail: poll while issuance is running, reload on state change
const banner = document.getElementById('progress-banner');
if (banner) {
  const certId = banner.dataset.certId;
  const initialStatus = document.getElementById('cert-status').textContent.trim();
  const shownChallenges = document.querySelectorAll('.panel .record-box').length;
  const poll = async () => {
    try {
      const res = await fetch(`/certificates/${certId}/status.json`, { headers: { accept: 'application/json' } });
      if (!res.ok) return;
      const data = await res.json();
      const pending = (data.pending_challenges || []).length;
      if (data.status !== initialStatus || pending !== shownChallenges) location.reload();
    } catch (_) { /* transient */ }
  };
  setInterval(poll, 4000);
}
