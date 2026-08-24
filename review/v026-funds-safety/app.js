const filterButtons = [...document.querySelectorAll("[data-filter]")];
const gateRows = [...document.querySelectorAll(".gate-row[data-domain]")];

for (const button of filterButtons) {
  button.addEventListener("click", () => {
    const selected = button.dataset.filter;
    for (const candidate of filterButtons) {
      candidate.classList.toggle("is-active", candidate === button);
      candidate.setAttribute("aria-pressed", candidate === button ? "true" : "false");
    }
    for (const row of gateRows) {
      row.classList.toggle(
        "is-hidden",
        selected !== "all" && row.dataset.domain !== selected,
      );
    }
  });
}

const navLinks = new Map(
  [...document.querySelectorAll("[data-nav]")].map((link) => [link.dataset.nav, link]),
);

const observer = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
    if (!visible) return;
    for (const link of navLinks.values()) link.classList.remove("is-active");
    navLinks.get(visible.target.id)?.classList.add("is-active");
  },
  { rootMargin: "-15% 0px -65% 0px", threshold: [0.05, 0.2, 0.5] },
);

for (const section of document.querySelectorAll("[data-section]")) observer.observe(section);
navLinks.get("verdict")?.classList.add("is-active");
