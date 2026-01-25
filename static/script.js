document.addEventListener("DOMContentLoaded", function () {
	const themeConfig = {
		default: { accent: "#667eea", accent2: "#764ba2", core: "#ffffff" },
		classic: { accent: "#8b6843", accent2: "#a0825a", core: "#ffffff" },
		coding: { accent: "#00ff41", accent2: "#00d1ff", core: "#0a0e14" },
		goofy: { accent: "#ff00ff", accent2: "#ffcc00", core: "#ffffff" },
		ocean: { accent: "#00b4d8", accent2: "#0077b6", core: "#ffffff" },
		sunset: { accent: "#ff6b6b", accent2: "#f06595", core: "#ffffff" },
		forest: { accent: "#2d6a4f", accent2: "#40916c", core: "#ffffff" },
	};

	const legacyTheme = localStorage.getItem("theme");
	if (legacyTheme && !localStorage.getItem("colorScheme") && !localStorage.getItem("uiTheme")) {
		if (["light", "dark", "auto"].includes(legacyTheme)) {
			localStorage.setItem("colorScheme", legacyTheme);
			localStorage.setItem("uiTheme", "default");
		} else {
			localStorage.setItem("uiTheme", legacyTheme);
			localStorage.setItem("colorScheme", "auto");
		}
		localStorage.removeItem("theme");
	}

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

	function setUiTheme(theme) {
		const normalized = theme || "default";
		document.documentElement.setAttribute("data-theme", normalized);
		localStorage.setItem("uiTheme", normalized);
		updateThemeMeta(normalized);
        updateFavicon();
	}

    function updateFavicon() {
        // scheme: light/dark
        const scheme = document.documentElement.getAttribute("data-bs-theme") || "light";
        const iconLink = document.querySelector("link[rel~='icon']");
        if (iconLink) {
             // If Dark Mode -> Use Dark Theme Icon (Black BG, White Text) which is favicon-theme-dark.png
             // If Light Mode -> Use Light Theme Icon (White BG, Black Text) which is favicon-theme-light.png
             // Note: data-bs-theme="dark" means the background is dark.
             
             if (scheme === "dark") {
                 iconLink.href = "/static/icons/favicon-theme-dark.png";
             } else {
                 iconLink.href = "/static/icons/favicon-theme-light.png";
             }
        }
    }

	function buildCursorSvg(primary, secondary, core, size) {
		return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 32 32"><circle cx="16" cy="16" r="12" fill="${primary}" opacity="0.4"/><circle cx="16" cy="16" r="8" fill="${secondary}" opacity="0.6"/><circle cx="16" cy="16" r="4" fill="${core}"/></svg>`;
	}

	function setCursor(primary, secondary, core) {
		const hoverSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 36 36"><circle cx="18" cy="18" r="16" fill="${primary}" opacity="0.9"/><circle cx="18" cy="18" r="12" fill="${secondary}"/><circle cx="18" cy="18" r="6" fill="${core}"/><path d="M22 16 L28 18 L22 20 Z" fill="${core}"/></svg>`;
		const baseSvg = buildCursorSvg(primary, secondary, core, 32);
		const styleId = "dynamic-cursor-style";
		let styleEl = document.getElementById(styleId);
		if (!styleEl) {
			styleEl = document.createElement("style");
			styleEl.id = styleId;
			document.head.appendChild(styleEl);
		}
		const baseUrl = `url('data:image/svg+xml;utf8,${encodeURIComponent(baseSvg)}') 16 16, auto`;
		const hoverUrl = `url('data:image/svg+xml;utf8,${encodeURIComponent(hoverSvg)}') 18 18, pointer`;
		styleEl.textContent = `html, body { cursor: ${baseUrl}; } a, button, .btn, input[type="submit"], .clickable { cursor: ${hoverUrl} !important; }`;
	}

	function setFavicon(color) {
		const favicon = document.getElementById("app-favicon");
		if (!favicon) return;
		const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stop-color="${color}"/><stop offset="1" stop-color="#ffffff"/></linearGradient></defs><rect width="128" height="128" rx="28" fill="url(#g)"/><path d="M36 88V40h18l20 22 20-22h18v48H94V68L74 90 54 68v20H36z" fill="#0a0e14" opacity="0.9"/></svg>`;
		favicon.href = `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
	}

	function setThemeColor(color) {
		const meta = document.querySelector('meta[name="theme-color"]');
		if (meta) meta.setAttribute("content", color);
	}

	function updateThemeMeta(theme) {
		const cfg = themeConfig[theme] || themeConfig.default;
		setCursor(cfg.accent, cfg.accent2, cfg.core);
		setThemeColor(cfg.accent);
		setFavicon(cfg.accent);
	}

	const storedScheme = localStorage.getItem("colorScheme") || "auto";
	const storedTheme = localStorage.getItem("uiTheme") || "default";
	setColorScheme(storedScheme);
	setUiTheme(storedTheme);

	const themeOptions = document.querySelectorAll(".theme-option");
	themeOptions.forEach((option) => {
		option.addEventListener("click", function (e) {
			e.preventDefault();
			const selectedTheme = this.getAttribute("data-theme");
			setUiTheme(selectedTheme);
		});
	});

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
