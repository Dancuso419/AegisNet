"use strict";

// ── Nav scroll state ─────────────────────────────────────
const nav = document.getElementById("lp-nav");
const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 20);
onScroll();
window.addEventListener("scroll", onScroll, { passive: true });

// ── Mobile hamburger menu ────────────────────────────────
const navToggle = document.getElementById("lp-nav-toggle");
const mobileMenu = document.getElementById("lp-mobile-menu");
if (navToggle && nav) {
  const setMenu = (open) => {
    nav.classList.toggle("menu-open", open);
    navToggle.setAttribute("aria-expanded", open ? "true" : "false");
  };
  navToggle.addEventListener("click", (e) => {
    e.stopPropagation();
    setMenu(!nav.classList.contains("menu-open"));
  });
  // Close on link tap, outside click, or scroll
  mobileMenu?.querySelectorAll("a").forEach((a) =>
    a.addEventListener("click", () => setMenu(false))
  );
  document.addEventListener("click", (e) => {
    if (!nav.contains(e.target)) setMenu(false);
  });
  window.addEventListener("scroll", () => setMenu(false), { passive: true });
}

// ── Scroll reveal (IntersectionObserver) ─────────────────
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      const delay = entry.target.dataset.delay || (i * 60);
      setTimeout(() => entry.target.classList.add("in"), delay);
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });

document.querySelectorAll(".reveal").forEach((el) => revealObserver.observe(el));

// ── 3D hero scene ────────────────────────────────────────
const stage = document.getElementById("scene-stage");
const scene = document.getElementById("hero-scene");
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;

if (stage && scene && !reduceMotion) {
  let targetX = 0, targetY = 0, curX = 0, curY = 0, rafId = null;

  const tick = () => {
    curX += (targetX - curX) * 0.08;
    curY += (targetY - curY) * 0.08;
    stage.style.transform = `rotateX(${curX.toFixed(2)}deg) rotateY(${curY.toFixed(2)}deg)`;
    if (Math.abs(targetX - curX) > 0.04 || Math.abs(targetY - curY) > 0.04) {
      rafId = requestAnimationFrame(tick);
    } else {
      rafId = null;
    }
  };
  const kick = () => { if (!rafId) rafId = requestAnimationFrame(tick); };
  const clamp = (v, m) => Math.max(-m, Math.min(m, v));

  const hoverable = matchMedia("(hover: hover) and (pointer: fine)").matches;

  if (hoverable) {
    // Desktop: mouse parallax
    window.addEventListener("mousemove", (e) => {
      const r = scene.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width  - 0.5;
      const py = (e.clientY - r.top)  / r.height - 0.5;
      targetY = px * 22;
      targetX = -py * 18;
      kick();
    }, { passive: true });
    scene.addEventListener("mouseleave", () => { targetX = 0; targetY = 0; kick(); });
  } else {
    // Touch: tilt the scene as it scrolls through the viewport
    const onSceneScroll = () => {
      const r = scene.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      const progress = ((r.top + r.height / 2) - vh / 2) / vh; // ~ -0.5..0.5
      targetX = clamp(-progress * 18, 14);
      targetY = clamp(progress * 20, 16);
      kick();
    };
    window.addEventListener("scroll", onSceneScroll, { passive: true });
    onSceneScroll();

    // Progressive enhancement: gyroscope tilt where available (Android,
    // and iOS only after a permission grant — silently ignored otherwise)
    window.addEventListener("deviceorientation", (e) => {
      if (e.gamma == null || e.beta == null) return;
      targetY = clamp(e.gamma * 0.5, 18);
      targetX = clamp((e.beta - 45) * 0.35, 14);
      kick();
    }, { passive: true });
  }
}

// ── Card tilt on hover (desktop only) ────────────────────
if (matchMedia("(hover: hover) and (pointer: fine)").matches) {
  document.querySelectorAll(".tilt").forEach((el) => {
    el.addEventListener("mousemove", (e) => {
      const r = el.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width  - 0.5;
      const py = (e.clientY - r.top)  / r.height - 0.5;
      el.style.transform =
        `perspective(900px) rotateX(${(-py * 7).toFixed(2)}deg) rotateY(${(px * 9).toFixed(2)}deg) translateY(-4px)`;
    });
    el.addEventListener("mouseleave", () => {
      el.style.transform = "perspective(900px) rotateX(0) rotateY(0) translateY(0)";
    });
  });
}

// ── Animated stat counters ───────────────────────────────
const statObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry) => {
    if (!entry.isIntersecting) return;
    const el = entry.target;
    const target = parseInt(el.dataset.count, 10);
    const suffix = el.dataset.suffix || "";
    const dur = 1400;
    const start = performance.now();
    const step = (now) => {
      const t = Math.min((now - start) / dur, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(eased * target) + suffix;
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
    statObserver.unobserve(el);
  });
}, { threshold: 0.5 });

document.querySelectorAll(".stat-num").forEach((el) => statObserver.observe(el));
