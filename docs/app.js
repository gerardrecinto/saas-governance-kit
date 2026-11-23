(function () {
  'use strict';
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Scroll progress bar
  var bar = document.querySelector('.scroll-progress');
  if (bar && !reduce) {
    var ticking = false;
    var update = function () {
      var h = document.documentElement.scrollHeight - window.innerHeight;
      bar.style.transform = 'scaleX(' + (h > 0 ? Math.min(1, window.scrollY / h) : 0) + ')';
      ticking = false;
    };
    window.addEventListener('scroll', function () {
      if (!ticking) { ticking = true; requestAnimationFrame(update); }
    }, { passive: true });
    update();
  }

  // Scroll reveal with staggered children. Content is visible by default; the js class is only set when motion is allowed.
  var items = document.querySelectorAll('.reveal');
  if (!reduce && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    items.forEach(function (el) { io.observe(el); });
    // Anything already past the viewport (anchor jumps, tall panels) is shown right away.
    window.addEventListener('load', function () {
      items.forEach(function (el) {
        if (el.getBoundingClientRect().top < window.innerHeight) el.classList.add('in');
      });
    });
  } else {
    items.forEach(function (el) { el.classList.add('in'); });
  }

  // Copy buttons. Hidden in the markup so they only appear when JS runs.
  var status = document.getElementById('copy-status');
  document.querySelectorAll('.copy').forEach(function (btn) {
    btn.hidden = false;
    btn.addEventListener('click', function () {
      var el = document.getElementById(btn.getAttribute('data-target'));
      if (!el) return;
      var text = el.innerText.replace(/\n+$/, '');
      function say(label, msg) {
        btn.textContent = label;
        if (status) status.textContent = msg;
        setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
      }
      function fallback() {
        try {
          var r = document.createRange(); r.selectNodeContents(el);
          var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
        } catch (e) { /* selection unsupported */ }
        say('Select and copy', 'Copy is not available here. The command is selected, press Ctrl or Command C.');
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { say('Copied', 'Command copied.'); }, fallback);
      } else { fallback(); }
    });
  });
})();
