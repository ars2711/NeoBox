document.addEventListener("DOMContentLoaded", function () {
	const validatorInput = document.querySelector(
		'form[action="https://validator.w3.org/check"] > input[name="fragment"]'
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

// On page load, set theme from localStorage
if (localStorage.getItem("theme") === "dark") {
	document.documentElement.setAttribute("data-bs-theme", "dark");
	document.getElementById("theme-icon").className = "bi bi-sun";
} else {
	document.documentElement.setAttribute("data-bs-theme", "light");
	document.getElementById("theme-icon").className = "bi bi-moon";
}

document.getElementById("theme-toggle").onclick = function () {
	const current = document.documentElement.getAttribute("data-bs-theme");
	const next = current === "dark" ? "light" : "dark";
	document.documentElement.setAttribute("data-bs-theme", next);
	localStorage.setItem("theme", next);
	document.getElementById("theme-icon").className =
		next === "dark" ? "bi bi-sun" : "bi bi-moon";
};

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

// Tools page instant search/filter with fade transitions and no grid gaps
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
		cards.forEach((card) => {
			const name = card.dataset.name ? card.dataset.name.toLowerCase() : "";
			if (!q || name.includes(q)) {
				// Show card
				if (card.classList.contains("hide")) {
					card.style.display = "";
					// Force reflow to restart transition
					void card.offsetWidth;
					card.classList.remove("hide");
				}
			} else {
				if (!card.classList.contains("hide")) {
					card.classList.add("hide");
				}
			}
		});
	}

	// After fade-out transition, set display:none
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
