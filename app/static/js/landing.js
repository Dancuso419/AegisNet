"use strict";

// ── Nav scroll state ─────────────────────────────────────
const nav = document.getElementById("lp-nav");
const onScroll = () => nav.classList.toggle("scrolled", window.scrollY > 20);
onScroll();
window.addEventListener("scroll", onScroll, { passive: true });

// ── Scroll reveal (IntersectionObserver) ─────────────────
const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      // Stagger siblings slightly for a cascade effect.
      const delay = entry.target.dataset.delay || (i * 60);
      setTimeout(() => entry.target.classList.add("in"), delay);
      revealObserver.unobserve(entry.target);
    }
  });
}, { threshold: 0.15, rootMargin: "0px 0px -40px 0px" });

document.querySelectorAll(".reveal").forEach((el) => revealObserver.observe(el));

// ── 3D hero scene — mouse parallax ───────────────────────
const stage = document.getElementById("scene-stage");
const scene = document.getElementById("hero-scene");

if (stage && scene && !matchMedia("(prefers-reduced-motion: reduce)").matches) {
  let targetX = 0, targetY = 0, curX = 0, curY = 0;
  let rafId = null;

  const onMove = (e) => {
    const r = scene.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width  - 0.5;  // -0.5 .. 0.5
    const py = (e.clientY - r.top)  / r.height - 0.5;
    targetY = px * 22;   // rotateY
    targetX = -py * 18;  // rotateX
    if (!rafId) rafId = requestAnimationFrame(tick);
  };

  const tick = () => {
    curX += (targetX - curX) * 0.08;
    curY += (targetY - curY) * 0.08;
    stage.style.transform = `rotateX(${curX.toFixed(2)}deg) rotateY(${curY.toFixed(2)}deg)`;
    if (Math.abs(targetX - curX) > 0.05 || Math.abs(targetY - curY) > 0.05) {
      rafId = requestAnimationFrame(tick);
    } else {
      rafId = null;
    }
  };

  const reset = () => {
    targetX = 0; targetY = 0;
    if (!rafId) rafId = requestAnimationFrame(tick);
  };

  window.addEventListener("mousemove", onMove, { passive: true });
  scene.addEventListener("mouseleave", reset);
}

// ── Card tilt on hover ───────────────────────────────────
const tiltEls = document.querySelectorAll(".tilt");
if (!matchMedia("(prefers-reduced-motion: reduce)").matches) {
  tiltEls.forEach((el) => {
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
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      el.textContent = Math.round(eased * target) + suffix;
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
    statObserver.unobserve(el);
  });
}, { threshold: 0.5 });

document.querySelectorAll(".stat-num").forEach((el) => statObserver.observe(el));
