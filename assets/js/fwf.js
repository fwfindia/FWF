/**
 * FWF Global Utilities
 * - Modern notification system (replaces alert/confirm)
 * - Shared header/footer injection
 * - Active nav management
 */

// ============ NOTIFICATION SYSTEM ============

window.FWF_Notify = {
  /**
   * Show toast notification
   * @param {string} message - Message to display
   * @param {string} type - 'success', 'error', 'warning', 'info'
   * @param {number} duration - Auto-hide duration in ms (0 = no auto-hide)
   */
  toast(message, type = 'info', duration = 4000) {
    const container = this._getContainer();
    const toast = document.createElement('div');
    toast.className = `fwf-toast fwf-toast-${type}`;
    
    const icons = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ'
    };
    
    toast.innerHTML = `
      <span class="fwf-toast-icon">${icons[type] || icons.info}</span>
      <span class="fwf-toast-message">${message}</span>
      <button class="fwf-toast-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(toast);
    
    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Auto-hide
    if (duration > 0) {
      setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
      }, duration);
    }
    
    return toast;
  },
  
  /**
   * Show modal dialog (replaces alert)
   * @param {object} options - {title, message, type, confirmText, onConfirm}
   */
  modal(options) {
    const {
      title = 'Notification',
      message,
      type = 'info',
      confirmText = 'OK',
      cancelText = null,
      onConfirm = null,
      onCancel = null
    } = options;
    
    const overlay = document.createElement('div');
    overlay.className = 'fwf-modal-overlay';
    
    const colors = {
      success: '#22c55e',
      error: '#ef4444',
      warning: '#f59e0b',
      info: '#3b82f6'
    };
    
    overlay.innerHTML = `
      <div class="fwf-modal">
        <div class="fwf-modal-header" style="border-left: 4px solid ${colors[type] || colors.info};">
          <h3>${title}</h3>
        </div>
        <div class="fwf-modal-body">
          <p>${message}</p>
        </div>
        <div class="fwf-modal-footer">
          ${cancelText ? `<button class="fwf-btn fwf-btn-secondary" data-action="cancel">${cancelText}</button>` : ''}
          <button class="fwf-btn fwf-btn-primary" data-action="confirm">${confirmText}</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(overlay);
    setTimeout(() => overlay.classList.add('show'), 10);
    
    // Handle clicks
    overlay.addEventListener('click', (e) => {
      if (e.target.classList.contains('fwf-modal-overlay')) {
        this._closeModal(overlay, onCancel);
      } else if (e.target.dataset.action === 'confirm') {
        this._closeModal(overlay, onConfirm);
      } else if (e.target.dataset.action === 'cancel') {
        this._closeModal(overlay, onCancel);
      }
    });
    
    return overlay;
  },
  
  /**
   * Show confirmation dialog (replaces confirm)
   */
  confirm(message, onConfirm, onCancel) {
    return this.modal({
      title: 'Confirm Action',
      message,
      type: 'warning',
      confirmText: 'Confirm',
      cancelText: 'Cancel',
      onConfirm,
      onCancel
    });
  },
  
  _getContainer() {
    let container = document.getElementById('fwf-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'fwf-toast-container';
      document.body.appendChild(container);
    }
    return container;
  },
  
  _closeModal(overlay, callback) {
    overlay.classList.remove('show');
    setTimeout(() => overlay.remove(), 300);
    if (callback) callback();
  }
};

// Inject notification styles
const notifyStyles = document.createElement('style');
notifyStyles.textContent = `
#fwf-toast-container{position:fixed;top:20px;right:20px;z-index:10000;display:flex;flex-direction:column;gap:12px;max-width:400px}
.fwf-toast{display:flex;align-items:center;gap:12px;padding:16px 20px;background:#fff;border-radius:12px;box-shadow:0 10px 40px rgba(0,0,0,.15);border-left:4px solid #3b82f6;opacity:0;transform:translateX(400px);transition:all .3s cubic-bezier(.68,-.55,.265,1.55)}
.fwf-toast.show{opacity:1;transform:translateX(0)}
.fwf-toast-success{border-left-color:#22c55e;background:linear-gradient(135deg,#f0fdf4,#dcfce7)}
.fwf-toast-error{border-left-color:#ef4444;background:linear-gradient(135deg,#fef2f2,#fee2e2)}
.fwf-toast-warning{border-left-color:#f59e0b;background:linear-gradient(135deg,#fffbeb,#fef3c7)}
.fwf-toast-info{border-left-color:#3b82f6;background:linear-gradient(135deg,#eff6ff,#dbeafe)}
.fwf-toast-icon{font-size:24px;font-weight:bold;flex-shrink:0}
.fwf-toast-success .fwf-toast-icon{color:#22c55e}
.fwf-toast-error .fwf-toast-icon{color:#ef4444}
.fwf-toast-warning .fwf-toast-icon{color:#f59e0b}
.fwf-toast-info .fwf-toast-icon{color:#3b82f6}
.fwf-toast-message{flex:1;font-weight:600;color:#1e293b;font-size:14px;line-height:1.5}
.fwf-toast-close{background:none;border:none;font-size:24px;color:#64748b;cursor:pointer;padding:0;line-height:1;transition:color .2s}
.fwf-toast-close:hover{color:#1e293b}
.fwf-modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);backdrop-filter:blur(4px);z-index:10001;display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity .3s}
.fwf-modal-overlay.show{opacity:1}
.fwf-modal{background:#fff;border-radius:20px;max-width:500px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,.3);transform:scale(.9);transition:transform .3s}
.fwf-modal-overlay.show .fwf-modal{transform:scale(1)}
.fwf-modal-header{padding:24px 28px;border-bottom:1px solid #e2e8f0}
.fwf-modal-header h3{margin:0;font-size:20px;font-weight:800;color:#1e293b}
.fwf-modal-body{padding:24px 28px}
.fwf-modal-body p{margin:0;color:#475569;font-size:15px;line-height:1.6}
.fwf-modal-footer{padding:20px 28px;display:flex;gap:12px;justify-content:flex-end;border-top:1px solid #f1f5f9}
.fwf-btn{padding:12px 24px;border:none;border-radius:10px;font-weight:700;font-size:14px;cursor:pointer;transition:all .2s}
.fwf-btn-primary{background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff}
.fwf-btn-primary:hover{transform:translateY(-2px);box-shadow:0 10px 25px rgba(99,102,241,.3)}
.fwf-btn-secondary{background:#f1f5f9;color:#475569}
.fwf-btn-secondary:hover{background:#e2e8f0}
@media(max-width:768px){
#fwf-toast-container{right:10px;left:10px;max-width:none}
.fwf-toast{padding:14px 16px}
.fwf-modal{max-width:95%}
}
`;
document.head.appendChild(notifyStyles);

// ============ HEADER/FOOTER INJECTION ============
(function(){
const current = (location.pathname.split('/').pop() || 'index.html').toLowerCase();


const header = `
<div class="topbar">
<div class="container">
<div class="row">
<div class="brand">
<img src="assets/images/logo.png" alt="FWF logo"/>
<div>
<div class="title">Foundris Welfare Foundation</div>
<div class="tag">Skill • Partnership • Prosperity</div>
</div>
</div>
<nav class="nav" id="nav">
<a class="nav-link" href="index.html" data-page="index.html">Home</a>
<a class="nav-link" href="about.html" data-page="about.html">About</a>
<a class="nav-link" href="programs.html" data-page="programs.html">Programs</a>
<a class="nav-link" href="projects.html" data-page="projects.html">Projects</a>
<a class="nav-link" href="join.html" data-page="join.html">Join</a>
<a class="nav-link" href="donate.html" data-page="donate.html">Donate</a>
<a class="nav-link" href="contact.html" data-page="contact.html">Contact</a>
</nav>
<button class="nav-toggle" id="nav-toggle">Menu</button>
</div>
</div>
</div>`;


const footer = `
<div class="footer">
<div class="container">
<div class="row">
<div>
<h5>About FWF</h5>
<p>FWF members ko skill training, cohort partnerships aur live outsource/CSR projects ke through sustainable income banane me madad karta hai.</p>
</div>
<div>
<h5>Quick Links</h5>
<p><a href="programs.html">Programs</a><br>
<a href="projects.html">Live Projects</a><br>
<a href="join.html">Membership</a><br>
<a href="donate.html">Donate</a></p>
</div>
<div>
<h5>Contact</h5>
<p><a href="mailto:info@fwfindia.org">info@fwfindia.org</a><br>
1398/1850 Sagarpuri Gallamandi, Kanpur - 208021 U.P India</p>
</div>
</div>
<div class="bottom">
<div>© <span id="year"></span> Foundris Welfare Foundation • All rights reserved.</div>
<div>
<a href="#">Privacy</a> · <a href="#">Terms</a>
</div>
</div>
</div>
</div>`;


})();