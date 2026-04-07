document.addEventListener("DOMContentLoaded", function () {
	const legacyTheme = localStorage.getItem("theme");
	if (legacyTheme && !localStorage.getItem("colorScheme")) {
		if (["light", "dark", "auto"].includes(legacyTheme)) {
			localStorage.setItem("colorScheme", legacyTheme);
		}
		localStorage.removeItem("theme");
	}
	localStorage.removeItem("uiTheme");

	function resolveColorScheme(scheme) {
		const prefersDark =
			window.matchMedia &&
			window.matchMedia("(prefers-color-scheme: dark)").matches;
		return scheme === "auto" ? (prefersDark ? "dark" : "light") : scheme;
	}

	function setColorScheme(scheme) {
		const resolved = resolveColorScheme(scheme);
		document.documentElement.setAttribute("data-bs-theme", resolved);
		localStorage.setItem("colorScheme", scheme);
		updateFavicon();
	}

	function updateFavicon() {
		const scheme = document.documentElement.getAttribute("data-bs-theme") || "light";
		const iconLink = document.querySelector("link[rel~='icon']");
		if (iconLink) {
			iconLink.href = scheme === "dark"
				? "/static/icons/favicon-theme-dark.png"
				: "/static/icons/favicon-theme-light.png";
		}
	}

	const storedScheme = localStorage.getItem("colorScheme") || "auto";
	setColorScheme(storedScheme);
	document.documentElement.setAttribute("data-theme", "default");

	const schemeOptions = document.querySelectorAll(".scheme-option");
	schemeOptions.forEach((option) => {
		option.addEventListener("click", function (e) {
			e.preventDefault();
			const selectedScheme = this.getAttribute("data-scheme");
			setColorScheme(selectedScheme);
		});
	});

	if (window.matchMedia) {
		const schemeQuery = window.matchMedia("(prefers-color-scheme: dark)");
		schemeQuery.addEventListener("change", () => {
			const current = localStorage.getItem("colorScheme") || "auto";
			setColorScheme(current);
		});
	}

	const validatorInput = document.querySelector(
		'form[action="https://validator.w3.org/check"] > input[name="fragment"]',
	);
	if (validatorInput) {
		const html =
			"<!DOCTYPE " +
			document.doctype.name +
			(document.doctype.publicId
				? ' PUBLIC "' + document.doctype.publicId + '"'
				: "") +
			(!document.doctype.publicId && document.doctype.systemId
				? " SYSTEM"
				: "") +
			(document.doctype.systemId
				? ' "' + document.doctype.systemId + '"'
				: "") +
			">\n" +
			document.documentElement.outerHTML;
		validatorInput.value = html;
	}
});

// Fade out on link click
document.addEventListener("DOMContentLoaded", function () {
	const mainContent = document.getElementById("main-content");
	document
		.querySelectorAll('a[href]:not([target="_blank"]):not([href^="#"])')
		.forEach(function (link) {
			link.addEventListener("click", function (e) {
				// Only fade if navigating within the site
				if (
					link.hostname === window.location.hostname &&
					!link.hasAttribute("data-no-fade")
				) {
					e.preventDefault();
					mainContent.classList.remove("fade-in");
					mainContent.classList.add("fade-out");
					setTimeout(function () {
						window.location = link.href;
					}, 300); // Match the CSS transition duration
				}
			});
		});
});

// Fade in on page load
window.addEventListener("pageshow", function () {
	const mainContent = document.getElementById("main-content");
	if (mainContent) {
		mainContent.classList.remove("fade-out");
		mainContent.classList.add("fade-in");
	}
});

document.addEventListener("DOMContentLoaded", function () {
	const searchInput = document.getElementById("toolSearch");
	if (!searchInput) return;

	const cards = Array.from(document.querySelectorAll(".tool-card"));

	// Ensure all cards are visible and not hidden on load
	cards.forEach((card) => {
		card.classList.remove("hide");
		card.style.display = "";
	});
	function filterTools() {
		const q = searchInput.value.trim().toLowerCase();
		const delay = 30;
		let visibleCount = 0;

		// First, add 'hide' class to all cards that should be hidden
		cards.forEach((card) => {
			const name = card.dataset.name ? card.dataset.name.toLowerCase() : "";
			const category = card.dataset.category
				? card.dataset.category.toLowerCase()
				: "";
			const shouldShow = !q || name.includes(q) || category.includes(q);

			if (!shouldShow && !card.classList.contains("hide")) {
				card.classList.add("hide");
			}
		});

		setTimeout(() => {
			cards.forEach((card, index) => {
				const name = card.dataset.name ? card.dataset.name.toLowerCase() : "";
				const category = card.dataset.category
					? card.dataset.category.toLowerCase()
					: "";
				const shouldShow = !q || name.includes(q) || category.includes(q);

				if (shouldShow) {
					visibleCount++;
					setTimeout(() => {
						if (card.classList.contains("hide")) {
							card.style.display = "";
							// Force reflow to restart transition
							void card.offsetWidth;
							card.classList.remove("hide");
						}
					}, index * delay);
				}
			});
		}, 100);
	}

	cards.forEach((card) => {
		card.addEventListener("transitionend", function (e) {
			if (e.propertyName === "opacity" && card.classList.contains("hide")) {
				card.style.display = "none";
			}
		});
	});

	searchInput.addEventListener("input", filterTools);
	searchInput.addEventListener("keyup", function (e) {
		if (e.key === "Enter") filterTools();
	});
});

// Service Worker registration
if ("serviceWorker" in navigator) {
	window.addEventListener("load", () => {
		navigator.serviceWorker
			.register("/static/service-worker.js")
			.then((reg) => console.log("✅ Service worker registered!", reg))
			.catch((err) => console.error("❌ SW registration failed: ", err));
	});
}

/* ============================================================
   ENHANCED INTERACTIONS � 2026 UPDATE
   ============================================================ */

// -- Scroll Progress Indicator ----------------------------------
(function () {
  const bar = document.createElement("div");
  bar.className = "scroll-indicator";
  document.body.prepend(bar);
  window.addEventListener("scroll", () => {
    const scrolled = window.scrollY;
    const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.width = (maxScroll > 0 ? (scrolled / maxScroll) * 100 : 0) + "%";
  }, { passive: true });
})();

// -- Orb Background ---------------------------------------------
(function () {
  for (let i = 1; i <= 3; i++) {
    const orb = document.createElement("div");
    orb.className = "orb-bg orb-" + i;
    document.body.appendChild(orb);
  }
})();

// -- Navbar Scroll State ----------------------------------------
(function () {
  const nav = document.querySelector(".navbar");
  if (!nav) return;
  const onScroll = () => nav.classList.toggle("navbar-scrolled", window.scrollY > 30);
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
})();

// -- Ripple Effect on Buttons -----------------------------------
document.addEventListener("click", function (e) {
  const btn = e.target.closest(".btn");
  if (!btn) return;
  const rect = btn.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const ripple = document.createElement("span");
  ripple.className = "ripple-effect";
  ripple.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - rect.left - size / 2}px;top:${e.clientY - rect.top - size / 2}px`;
  btn.appendChild(ripple);
  ripple.addEventListener("animationend", () => ripple.remove());
});

// -- Mouse-tracking Spotlight on Cards -------------------------
document.addEventListener("mousemove", function (e) {
  const card = e.target.closest(".tool-card, .spotlight-card");
  if (!card) return;
  const r = card.getBoundingClientRect();
  card.style.setProperty("--mouse-x", (e.clientX - r.left) + "px");
  card.style.setProperty("--mouse-y", (e.clientY - r.top) + "px");
});

// -- Scroll-reveal (IntersectionObserver) ---------------------
(function () {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("revealed");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: "0px 0px -40px 0px" }
  );
  const autoReveal = document.querySelectorAll(
    ".feature-card, .tool-card, .dashboard-stat-card, " +
    ".marquee-wrapper, .stats-row, .cta-section, .accordion, .reveal"
  );
  autoReveal.forEach((el, i) => {
    el.classList.add("reveal");
    if (i < 6) el.classList.add("reveal-delay-" + ((i % 6) + 1));
    observer.observe(el);
  });
})();

// -- Animated Counters -----------------------------------------
(function () {
  const countEls = document.querySelectorAll("[data-count]");
  if (!countEls.length) return;
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        const el = entry.target;
        const target = parseInt(el.dataset.count, 10);
        const suffix = el.dataset.countSuffix || "";
        const duration = 1800;
        const start = performance.now();
        const tick = (now) => {
          const prog = Math.min((now - start) / duration, 1);
          const ease = 1 - Math.pow(1 - prog, 3);
          el.textContent = Math.floor(ease * target).toLocaleString() + suffix;
          if (prog < 1) requestAnimationFrame(tick);
        };
        requestAnimationFrame(tick);
        observer.unobserve(el);
      });
    },
    { threshold: 0.4 }
  );
  countEls.forEach((el) => observer.observe(el));
})();

// -- Tilt Effect on Feature Cards -----------------------------
(function () {
  document.addEventListener("mousemove", function (e) {
    const card = e.target.closest(".feature-card");
    if (!card) return;
    const r = card.getBoundingClientRect();
    const x = ((e.clientX - r.left) / r.width - 0.5) * 12;
    const y = ((e.clientY - r.top) / r.height - 0.5) * -12;
    card.style.transform = `translateY(-7px) scale(1.015) perspective(600px) rotateY(${x}deg) rotateX(${y}deg)`;
  });
  document.addEventListener("mouseleave", function (e) {
    const card = e.target.closest(".feature-card");
    if (!card) return;
    card.style.transform = "";
  }, true);
})();

// -- Staggered Entrance for Grid Items ------------------------
(function () {
  document.querySelectorAll(".tool-grid .tool-card, .row.g-3 > *").forEach((el, i) => {
    el.style.transitionDelay = (i * 0.04) + "s";
  });
})();

// -- Auto-dismiss flash alerts ---------------------------------
(function () {
  document.querySelectorAll(".alert-dismissible").forEach((alert) => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 5500);
  });
})();
