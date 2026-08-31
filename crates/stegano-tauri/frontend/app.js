/* ============================================================
   SteganoHero, desktop interface logic.

   No user-visible string lives in this file. Every label, hint
   and message is read from a catalogue in locales/<code>.json
   through t(key). The guardrail test
   "no_user_visible_literals_in_the_interface" fails the build
   if that stops being true.
   ============================================================ */

const STORAGE_LOCALE = "steganohero.locale";
const STORAGE_THEME = "steganohero.theme";

const TAB_IDS = ["compose", "decode", "analyze", "provenance", "canary", "airegulation", "files", "decoder", "settings", "restmcp", "about"];

/* The confidentiality layers a document may default to when none is named.
   The "none" entry is offered too, exactly as the engine allows. Identifiers
   only: each name comes from the catalogue, like the cipher options on Compose. */
const SETTINGS_CIPHER_NONE = "none";
const THEME_MODES = ["system", "light", "dark"];

/* Bindings offered on the Provenance tab. Identifiers only: the name and the
   note for each come from the catalogue, exactly like carriers and ciphers. */
const BINDING_IDS = ["detached", "in_band"];

/* Missions offered on Compose (backlog UI-mission). Identifiers only: the name
   for each comes from the catalogue. The recommended density and range come from
   the backend, so the interface never restates the core's figures. */
const MISSION_IDS = ["conceal", "sign", "mark"];

/* The forensic verdict rides back as its Display form; this maps it to the
   catalogue key already used by the Analyze tab, so one wording serves both. */
const VERDICT_KEYS = {
  CLEAN: "Clean",
  SUSPICIOUS: "Suspicious",
  MODIFIED: "Modified",
  CONFIRMED: "Confirmed",
};

/* The robustness classes the core reports, mapped to their catalogue label.
   The note beside each is measured text the backend returns, shown as it is. */
const ROBUSTNESS_KEY = {
  High: "provenance.robustness.high",
  BestEffort: "provenance.robustness.best_effort",
  FormatBound: "provenance.robustness.format_bound",
};

const state = {
  catalogue: {},
  locale: "en",
  locales: [],
  baseLocale: "en",
  environmentHint: null,
  localeDirectory: "",
  carriers: [],
  ciphers: [],
  exportFormats: [],
  requiredBits: null,
  capacities: [],
  mission: MISSION_IDS[0],
  /* The chosen fill ratio, or null to take the mission's recommended value. */
  density: null,
  /* The recovery-robust heavy frame is an opt-in; the light frame is the default
     base of the multi-pass composition (COMPOSE-2). */
  robust: false,
  /* Saturation: the aggressive variant that fills the channel with the secret
     repeated. Overrides robust when on (SATURATE). */
  saturate: false,
  activeTab: TAB_IDS[0],
  appInfo: null,
  /* The runtime engine configuration read back from the core, and the accepted
     range of every field. Both come from settings_read; the interface never
     restates the core's own figures. */
  settings: null,
  settingsConstraints: null,
};

/* ─── Backend bridge ───────────────────────────────────────── */

function invoke(command, args) {
  if (window.__TAURI__ && window.__TAURI__.core) {
    return window.__TAURI__.core.invoke(command, args);
  }
  return Promise.reject(new Error("__TAURI__.core.invoke is unavailable"));
}

/* ─── Catalogue ────────────────────────────────────────────── */

function t(key) {
  const value = state.catalogue[key];
  return value === undefined ? key : value;
}

function setText(element, key) {
  element.textContent = t(key);
}

/* ─── Small DOM helpers ────────────────────────────────────── */

function el(tag, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function fmtInt(value) {
  return new Intl.NumberFormat(state.locale).format(value);
}

function fmtFixed(value, digits) {
  return new Intl.NumberFormat(state.locale, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(value);
}

function fmtPercent(ratio) {
  return new Intl.NumberFormat(state.locale, {
    style: "percent",
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(ratio);
}

function keyValue(container, labelKey, value) {
  const item = el("div", "kv-item");
  const key = el("span", "kv-key");
  setText(key, labelKey);
  const val = el("span", "kv-value");
  val.textContent = value;
  item.appendChild(key);
  item.appendChild(val);
  container.appendChild(item);
  return item;
}

function showCallout(container, variant, message) {
  clear(container);
  const box = el("div", variant ? "callout callout--" + variant : "callout");
  box.textContent = message;
  container.appendChild(box);
}

function showCalloutKey(container, variant, key) {
  showCallout(container, variant, t(key));
}

function describeError(error) {
  if (error === null || error === undefined) return "";
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}

/* ─── Status bar ───────────────────────────────────────────── */

let statusTimer = null;

function setStatus(key) {
  const node = document.getElementById("status-message");
  setText(node, key);
  if (statusTimer) clearTimeout(statusTimer);
  if (key === "status.done" || key === "status.copied") {
    statusTimer = setTimeout(() => {
      node.textContent = "";
    }, 2600);
  }
}

/* ─── Translation application ──────────────────────────────── */

const ATTRIBUTE_BINDINGS = [
  ["data-i18n-placeholder", "placeholder"],
  ["data-i18n-title", "title"],
  ["data-i18n-aria-label", "aria-label"],
];

function applyCatalogue() {
  document.documentElement.setAttribute("lang", state.locale);
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    setText(node, node.getAttribute("data-i18n"));
  });
  ATTRIBUTE_BINDINGS.forEach(([source, target]) => {
    document.querySelectorAll("[" + source + "]").forEach((node) => {
      node.setAttribute(target, t(node.getAttribute(source)));
    });
  });
  renderTabs();
  renderThemePicker();
  renderLanguagePicker();
  renderCarrierChips();
  renderMissionChips();
  renderCipherOptions();
  renderDecodeCarrierOptions();
  renderBindingOptions();
  renderMarkCarrierOptions();
  renderVerifyCarrierChips();
  renderSettingsCipherOptions();
  paintSettingsReadback();
  renderBuildInfo();
  // The mission readout is a persistent control, so a locale change must
  // re-localise its labels and verdict, not only the static markup above.
  refreshMission();
  setStatus("status.ready");
}

/* ─── Locale resolution ────────────────────────────────────── */

function matchLocale(wanted, available) {
  if (!wanted) return null;
  const normalised = wanted.toLowerCase();
  const exact = available.find((entry) => entry.code.toLowerCase() === normalised);
  if (exact) return exact.code;
  const base = normalised.split("-")[0];
  const partial = available.find((entry) => entry.code.toLowerCase().split("-")[0] === base);
  return partial ? partial.code : null;
}

/* Resolution order: a language chosen previously, then the languages the
   system reports through the web view, then the process environment, then
   the base catalogue. */
function resolveLocale(available, environmentHint, baseLocale) {
  const stored = window.localStorage.getItem(STORAGE_LOCALE);
  const fromStorage = matchLocale(stored, available);
  if (fromStorage) return fromStorage;

  const reported = navigator.languages && navigator.languages.length
    ? navigator.languages
    : [navigator.language];
  for (const candidate of reported) {
    const match = matchLocale(candidate, available);
    if (match) return match;
  }

  const fromEnvironment = matchLocale(environmentHint, available);
  if (fromEnvironment) return fromEnvironment;

  return matchLocale(baseLocale, available) || available[0].code;
}

async function setLocale(code, remember) {
  state.catalogue = await invoke("load_locale", { code });
  state.locale = code;
  if (remember) window.localStorage.setItem(STORAGE_LOCALE, code);
  applyCatalogue();
}

/* ─── Theme ────────────────────────────────────────────────── */

function currentThemeMode() {
  const stored = window.localStorage.getItem(STORAGE_THEME);
  return THEME_MODES.includes(stored) ? stored : "system";
}

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "system") {
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", mode);
  }
  window.localStorage.setItem(STORAGE_THEME, mode);
  renderThemePicker();
}

function renderThemePicker() {
  const picker = document.getElementById("theme-picker");
  const active = currentThemeMode();
  clear(picker);
  THEME_MODES.forEach((mode) => {
    const button = el("button");
    button.type = "button";
    setText(button, "chrome.theme." + mode);
    button.setAttribute("aria-pressed", active === mode ? "true" : "false");
    button.addEventListener("click", () => applyTheme(mode));
    picker.appendChild(button);
  });
}

function renderLanguagePicker() {
  const picker = document.getElementById("language-picker");
  clear(picker);
  state.locales.forEach((entry) => {
    const button = el("button");
    button.type = "button";
    button.textContent = entry.display_name;
    button.setAttribute("aria-pressed", entry.code === state.locale ? "true" : "false");
    button.addEventListener("click", () => {
      setLocale(entry.code, true).catch(reportFatal);
    });
    picker.appendChild(button);
  });
}

/* ─── Tabs ─────────────────────────────────────────────────── */

function renderTabs() {
  const strip = document.getElementById("tabstrip");
  clear(strip);
  TAB_IDS.forEach((id) => {
    const tab = el("button", "tab");
    tab.type = "button";
    tab.id = "tab-" + id;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-controls", "view-" + id);
    tab.setAttribute("aria-selected", state.activeTab === id ? "true" : "false");
    tab.tabIndex = state.activeTab === id ? 0 : -1;
    setText(tab, "nav." + id);
    tab.addEventListener("click", () => selectTab(id));
    tab.addEventListener("keydown", (event) => onTabKey(event, id));
    strip.appendChild(tab);
  });
}

function onTabKey(event, id) {
  const index = TAB_IDS.indexOf(id);
  let next = null;
  if (event.key === "ArrowRight") next = TAB_IDS[(index + 1) % TAB_IDS.length];
  if (event.key === "ArrowLeft") next = TAB_IDS[(index - 1 + TAB_IDS.length) % TAB_IDS.length];
  if (event.key === "Home") next = TAB_IDS[0];
  if (event.key === "End") next = TAB_IDS[TAB_IDS.length - 1];
  if (!next) return;
  event.preventDefault();
  selectTab(next);
  document.getElementById("tab-" + next).focus();
}

function selectTab(id) {
  state.activeTab = id;
  TAB_IDS.forEach((candidate) => {
    const tab = document.getElementById("tab-" + candidate);
    const view = document.getElementById("view-" + candidate);
    const selected = candidate === id;
    tab.setAttribute("aria-selected", selected ? "true" : "false");
    tab.tabIndex = selected ? 0 : -1;
    view.hidden = !selected;
  });
  const view = document.getElementById("view-" + id);
  // Restart the entrance animation so the panel change reads as a move.
  view.style.animation = "none";
  void view.offsetWidth;
  view.style.animation = "";
  document.getElementById("workspace").scrollTop = 0;
  // The Rest/mcp tab reads the live setup each time it opens, so it reflects the
  // current binary location and which clients are present now.
  if (id === "restmcp") renderRestMcp();
}

/* ─── Compose ──────────────────────────────────────────────── */

function selectedCarriers() {
  return Array.from(
    document.querySelectorAll("#compose-carriers input[type=checkbox]")
  )
    .filter((box) => box.checked)
    .map((box) => box.value);
}

/* Whether the engine can currently read a layer back out of this carrier.
   Measured by the backend at startup, never assumed here. */
function carrierReadsBack(id) {
  const entry = state.capacities.find((item) => item.id === id);
  return entry ? entry.round_trip_verified : true;
}

function renderCarrierChips() {
  const grid = document.getElementById("compose-carriers");
  const previous = new Set(selectedCarriers());
  clear(grid);

  state.carriers.forEach((id, index) => {
    const chip = el("label", "chip");
    const box = el("input");
    box.type = "checkbox";
    box.value = id;
    box.checked = previous.size ? previous.has(id) : index === 0;
    chip.setAttribute("data-checked", box.checked ? "true" : "false");
    box.addEventListener("change", () => {
      chip.setAttribute("data-checked", box.checked ? "true" : "false");
      refreshCapacity();
      refreshMission();
      checkComposition();
    });

    const body = el("div");
    const name = el("div", "chip-name");
    setText(name, "carrier." + id + ".name");
    body.appendChild(name);

    if (!carrierReadsBack(id)) {
      const flag = el("span", "badge badge--warning");
      setText(flag, "compose.carriers.read_path_broken");
      body.appendChild(flag);
    }

    const note = el("div", "chip-note");
    setText(note, "carrier." + id + ".note");
    body.appendChild(note);

    if (!carrierReadsBack(id)) {
      const detail = el("div", "chip-note");
      setText(detail, "compose.carriers.read_path_broken_detail");
      body.appendChild(detail);
    }

    const meterRow = el("div", "chip-meter");
    const meter = el("span", "meter");
    const fill = el("span", "meter-fill");
    fill.id = "meter-" + id;
    meter.appendChild(fill);
    const readout = el("span");
    readout.id = "capacity-" + id;
    meterRow.appendChild(meter);
    meterRow.appendChild(readout);

    chip.appendChild(box);
    chip.appendChild(body);
    chip.appendChild(meterRow);
    grid.appendChild(chip);
  });

  paintCapacity();
}

function renderCipherOptions() {
  const select = document.getElementById("compose-cipher");
  const previous = select.value;
  clear(select);

  const none = el("option");
  none.value = "none";
  setText(none, "cipher.none.name");
  select.appendChild(none);

  state.ciphers.forEach((id) => {
    const option = el("option");
    option.value = id;
    setText(option, "cipher." + id + ".name");
    select.appendChild(option);
  });

  // The recipient mode is a frontend-only menu entry: it seals to a public key
  // instead of a passphrase, so it is not one of the catalogue's passphrase
  // ciphers. Selecting it swaps the passphrase field for the public-key field.
  const recipient = el("option");
  recipient.value = "recipient_pqc";
  setText(recipient, "cipher.recipient_pqc.name");
  select.appendChild(recipient);

  select.value = previous || "none";
  if (!select.value) select.value = "none";
  paintCipherNote();
}

function paintCipherNote() {
  const select = document.getElementById("compose-cipher");
  const note = document.getElementById("compose-cipher-note");
  setText(note, "cipher." + select.value + ".note");
  const isRecipient = select.value === "recipient_pqc";
  // Swap the two confidentiality inputs: a passphrase for the ciphers, a
  // recipient public key for the recipient mode. Only one is ever visible.
  document.getElementById("compose-password-field").hidden = isRecipient;
  document.getElementById("compose-recipient-field").hidden = !isRecipient;
  const password = document.getElementById("compose-password");
  password.disabled = select.value === "none" || isRecipient;
}

function renderDecodeCarrierOptions() {
  const select = document.getElementById("decode-carrier");
  const previous = select.value;
  clear(select);

  const auto = el("option");
  auto.value = "";
  setText(auto, "decode.carriers.auto");
  select.appendChild(auto);

  state.carriers.forEach((id) => {
    const option = el("option");
    option.value = id;
    setText(option, "carrier." + id + ".name");
    select.appendChild(option);
  });
  select.value = previous || "";
}

function paintCapacity() {
  const required = state.requiredBits;
  const requiredNode = document.getElementById("compose-required");
  requiredNode.textContent = required === null
    ? t("compose.capacity.unmeasured")
    : fmtInt(required) + " " + t("compose.capacity.bits");

  state.capacities.forEach((entry) => {
    const fill = document.getElementById("meter-" + entry.id);
    const readout = document.getElementById("capacity-" + entry.id);
    if (!fill || !readout) return;

    /* The carrier the cover does not bound places by extending the document,
       so it holds no fixed limit here. */
    if (!entry.cover_bounds_writes) {
      fill.style.transform = "scaleX(1)";
      readout.textContent = t("compose.capacity.unlimited");
      return;
    }
    /* What a framed document holds, measured against the layer a secret needs.
       The raw position count is not compared: a framed document is larger than
       the secret it carries, so comparing raw positions would overstate room. */
    const available = entry.framed_bytes * 8;
    const ratio = required === null || required === 0
      ? 0
      : Math.min(1, available / required);
    fill.style.transform = "scaleX(" + ratio + ")";
    const label = fmtInt(available) + " " + t("compose.capacity.bits");
    readout.textContent = required === null
      ? label
      : label + " " + (available >= required
        ? t("compose.capacity.sufficient")
        : t("compose.capacity.insufficient"));
  });
}

/* Ask the engine whether the current selection is a legal composition, so an
   illegal one is refused at selection time rather than after composing. */
function checkComposition() {
  const selection = selectedCarriers();
  const run = document.getElementById("compose-run");
  const message = document.getElementById("compose-message");
  if (!selection.length) {
    run.disabled = false;
    return;
  }
  invoke("validate_carriers", { carriers: selection })
    .then(() => {
      run.disabled = false;
      clear(message);
    })
    .catch((error) => {
      run.disabled = true;
      showCallout(message, "danger",
        t("compose.carriers.invalid_combination") + " " + describeError(error));
    });
}

let capacityTimer = null;

function refreshCapacity() {
  if (capacityTimer) clearTimeout(capacityTimer);
  capacityTimer = setTimeout(() => {
    const cover = document.getElementById("compose-cover").value;
    invoke("carrier_capacity", { cover, robust: state.robust })
      .then((report) => {
        state.capacities = report;
        paintCapacity();
      })
      .catch((error) => {
        showCallout(document.getElementById("compose-message"), "danger", describeError(error));
      });
  }, 250);
}

/* ─── Mission and density (backlog UI-mission) ─────────────── */

/* Draw the three mission options as single-select chips. The recommended
   density and the range for each come from the backend, never restated here. */
function renderMissionChips() {
  const grid = document.getElementById("compose-missions");
  clear(grid);

  MISSION_IDS.forEach((id) => {
    const chip = el("label", "chip");
    const box = el("input");
    box.type = "radio";
    box.name = "compose-mission";
    box.setAttribute("data-mission", id);
    box.checked = id === state.mission;
    chip.setAttribute("data-checked", box.checked ? "true" : "false");
    box.addEventListener("change", () => selectMission(id));

    const body = el("div");
    const name = el("div", "chip-name");
    setText(name, "compose.mission." + id);
    body.appendChild(name);

    chip.appendChild(box);
    chip.appendChild(body);
    grid.appendChild(chip);
  });
}

/* A new mission resets the slider to that mission's recommended value, which the
   backend supplies, so the default cannot drift from the engine's own gate. */
function selectMission(id) {
  state.mission = id;
  state.density = null;
  document.querySelectorAll("#compose-missions .chip").forEach((chip) => {
    const input = chip.querySelector("input");
    chip.setAttribute("data-checked", input && input.checked ? "true" : "false");
  });
  refreshMission();
}

function onDensityInput() {
  const slider = document.getElementById("compose-density");
  state.density = parseFloat(slider.value);
  document.getElementById("compose-density-value").textContent = fmtPercent(state.density);
  refreshMission();
}

let missionTimer = null;

/* Ask the backend for the mission-gated capacity and, when a secret is present,
   the verdict the analyser returns on the document this mission would produce.
   Debounced, because with a cipher selected the produced document is composed. */
function refreshMission() {
  if (missionTimer) clearTimeout(missionTimer);
  missionTimer = setTimeout(() => {
    const cover = document.getElementById("compose-cover").value;
    const secret = document.getElementById("compose-secret").value;
    const cipher = document.getElementById("compose-cipher").value;
    const password = document.getElementById("compose-password").value;
    /* A cipher only shapes the produced document once a passphrase is present;
       without one the preview reflects the unencrypted layer rather than a
       refusal, and the real refusal still lands at compose time. */
    const useCipher = cipher !== "none" && cipher !== "recipient_pqc" && Boolean(password);
    /* Recipient mode seals with a fixed overhead this preview cannot size, so the
       secret is withheld here: the density range still shows, the fit verdict is
       left to compose, which refuses by name if the sealed layer will not fit. */
    const isRecipient = cipher === "recipient_pqc";

    invoke("mission_capacity", {
      request: {
        cover,
        carriers: selectedCarriers(),
        mission: state.mission,
        density: state.density,
        secret: !isRecipient && secret.trim() ? secret : null,
        cipher: useCipher ? cipher : null,
        password: useCipher ? password : null,
        robust: state.robust,
      },
    })
      .then((response) => paintMissionReadout(response))
      .catch((error) => {
        showCallout(
          document.getElementById("compose-mission-message"),
          "danger",
          describeError(error)
        );
      });
  }, 250);
}

/* Paint the slider from the mission's range and the readout from the response.
   The verdict and the resulting density are measured on the produced document,
   never asserted; a refusal shows the mission's named arithmetic instead. */
function paintMissionReadout(response) {
  const slider = document.getElementById("compose-density");
  slider.min = response.min_density;
  slider.max = response.max_density;
  slider.step = 0.01;
  slider.value = response.density;
  state.density = response.density;
  document.getElementById("compose-density-value").textContent = fmtPercent(response.density);

  const readout = document.getElementById("compose-mission-readout");
  clear(readout);
  keyValue(readout, "compose.mission.recommended", fmtPercent(response.recommended_density));
  keyValue(
    readout,
    "compose.mission.effective",
    fmtInt(response.effective_capacity_bytes) + " " + t("compose.mission.bytes")
  );

  const message = document.getElementById("compose-mission-message");
  clear(message);

  if (response.fits === true) {
    keyValue(readout, "compose.mission.density_result", fmtPercent(response.noise_density || 0));
    const verdict = response.verdict || "";
    keyValue(
      readout,
      "compose.mission.verdict",
      t("analyze.verdict." + (VERDICT_KEYS[verdict] || verdict))
    );
  } else if (response.fits === false) {
    const filled = t("compose.mission.overflow")
      .replace("{needed}", fmtInt(response.needed_bits || 0))
      .replace("{available}", fmtInt(response.available_bits || 0));
    showCallout(message, "warning", filled);
  }
}

/* The recommendation overlay (COMPOSE-3). It weighs every carrier and mission
   for the current secret and cover, then names the most discreet setting that
   holds the load without overflow. The operator applies it in one click or
   ignores it; nothing is changed until Apply. */
function requestRecommendation() {
  const cover = document.getElementById("compose-cover").value;
  const secret = document.getElementById("compose-secret").value;
  const message = document.getElementById("compose-mission-message");
  if (!cover.trim() || !secret.trim()) {
    showCallout(message, "warning", t("compose.recommend.empty"));
    return;
  }
  const cipher = document.getElementById("compose-cipher").value;
  const password = document.getElementById("compose-password").value;
  /* A cipher shapes the size only once its passphrase is present; recipient
     sealing is left to compose, which refuses by name if the sealed layer will
     not fit. */
  const useCipher =
    cipher !== "none" && cipher !== "recipient_pqc" && Boolean(password);
  invoke("recommend_settings", {
    cover,
    secret,
    carriers: [],
    cipher: useCipher ? cipher : null,
    password: useCipher ? password : null,
    robust: state.robust,
  })
    .then((rec) => paintRecommendation(rec))
    .catch((error) => showCallout(message, "danger", describeError(error)));
}

function paintRecommendation(rec) {
  state.recommendation = rec;
  const panel = document.getElementById("compose-recommendation");
  const headline = document.getElementById("compose-recommendation-headline");
  const detail = document.getElementById("compose-recommendation-detail");
  const apply = document.getElementById("compose-recommendation-apply");
  clear(detail);

  if (rec.fits && rec.carrier && rec.mission) {
    headline.textContent = t("compose.recommend.fits")
      .replace("{carrier}", t("carrier." + rec.carrier + ".name"))
      .replace("{mission}", t("compose.mission." + rec.mission));
    keyValue(detail, "compose.recommend.carrier", t("carrier." + rec.carrier + ".name"));
    keyValue(detail, "compose.recommend.mission", t("compose.mission." + rec.mission));
    keyValue(detail, "compose.recommend.density", fmtPercent(rec.density || 0));
    const best = (rec.carriers || []).find((item) => item.carrier === rec.carrier);
    if (best) {
      keyValue(detail, "compose.recommend.fill", fmtPercent(best.fill_ratio || 0));
    }
    apply.hidden = false;
  } else {
    headline.textContent = t("compose.recommend.nofit").replace(
      "{shortfall}",
      fmtInt(rec.shortfall_bytes || 0)
    );
    apply.hidden = true;
  }
  panel.hidden = false;
}

/* Apply the standing recommendation: select the recommended carrier alone, then
   the recommended mission, whose selection resets the slider to that mission's
   recommended ceiling, which is the density the recommendation names. */
function applyRecommendation() {
  const rec = state.recommendation;
  if (!rec || !rec.fits || !rec.carrier || !rec.mission) return;

  document
    .querySelectorAll("#compose-carriers input[type=checkbox]")
    .forEach((box) => {
      box.checked = box.value === rec.carrier;
      const chip = box.closest(".chip");
      if (chip) chip.setAttribute("data-checked", box.checked ? "true" : "false");
    });

  const missionBox = document.querySelector(
    '#compose-missions input[data-mission="' + rec.mission + '"]'
  );
  if (missionBox) missionBox.checked = true;
  selectMission(rec.mission);
  refreshCapacity();
  hideRecommendation();
}

function hideRecommendation() {
  const panel = document.getElementById("compose-recommendation");
  if (panel) panel.hidden = true;
}

function composeValidationKey() {
  const secret = document.getElementById("compose-secret").value;
  const cover = document.getElementById("compose-cover").value;
  const cipher = document.getElementById("compose-cipher").value;
  const password = document.getElementById("compose-password").value;
  const recipientKey = document.getElementById("compose-recipient-key").value;
  if (!secret.trim()) return "compose.error.no_secret";
  if (!cover.trim()) return "compose.error.no_cover";
  if (!selectedCarriers().length) return "compose.error.no_carrier";
  if (cipher === "recipient_pqc") {
    if (!recipientKey.trim()) return "compose.error.no_recipient";
  } else if (cipher !== "none" && !password) {
    return "compose.error.no_password";
  }
  return null;
}

async function runMeasure() {
  const message = document.getElementById("compose-message");
  const secret = document.getElementById("compose-secret").value;
  const cipher = document.getElementById("compose-cipher").value;
  const password = document.getElementById("compose-password").value;
  if (!secret.trim()) {
    showCalloutKey(message, "warning", "compose.error.no_secret");
    return;
  }
  if (cipher === "recipient_pqc") {
    // The recipient seal adds a fixed post-quantum overhead this preview does not
    // size. The exact capacity is checked when you compose, which refuses by name
    // if the cover cannot hold the sealed layer, so nothing is silently dropped.
    showCalloutKey(message, "warning", "compose.recipient.measure_note");
    return;
  }
  if (cipher !== "none" && !password) {
    showCalloutKey(message, "warning", "compose.error.no_password");
    return;
  }
  setStatus("status.working");
  try {
    const size = await invoke("measure_payload", {
      secret,
      cipher: cipher === "none" ? null : cipher,
      password: password || null,
    });
    state.requiredBits = size.bits;
    paintCapacity();
    clear(message);
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* The reusable file-import handle for the cover, and the marked file held for
 * download after a successful file conceal. Both are set when Compose runs on a
 * loaded cover file, and reset when the input drops back to text or is cleared. */
let composeCoverImport = null;
let composeFileDownload = null;

async function runCompose() {
  // The file-import decides the path: a loaded cover file is concealed into and
  // its marked bytes are offered to download, the same way Analyze routes a
  // loaded file. With no file, the pasted cover text path below is unchanged.
  // The two paths stay cleanly separated.
  const held = composeCoverImport ? composeCoverImport.get() : null;
  if (held) {
    await runComposeFile(held);
    return;
  }

  const message = document.getElementById("compose-message");
  // The text path never offers a file download; hide any left by a file run.
  composeFileDownload = null;
  document.getElementById("compose-download").hidden = true;

  const problem = composeValidationKey();
  if (problem) {
    showCalloutKey(message, "warning", problem);
    return;
  }

  const cipher = document.getElementById("compose-cipher").value;
  const password = document.getElementById("compose-password").value;
  const isRecipient = cipher === "recipient_pqc";
  setStatus("status.working");

  try {
    const response = isRecipient
      ? await invoke("compose_sealed", {
          cover: document.getElementById("compose-cover").value,
          secret: document.getElementById("compose-secret").value,
          carriers: selectedCarriers(),
          recipient_public_key: document.getElementById("compose-recipient-key").value.trim(),
          robust: state.robust,
          saturate: state.saturate,
        })
      : await invoke("compose", {
          cover: document.getElementById("compose-cover").value,
          secret: document.getElementById("compose-secret").value,
          carriers: selectedCarriers(),
          cipher: cipher === "none" ? null : cipher,
          password: password || null,
          robust: state.robust,
          saturate: state.saturate,
        });

    clear(message);
    state.requiredBits = response.layer_bits;
    paintCapacity();

    document.getElementById("compose-output").value = response.stego_text;
    document.getElementById("compose-result").hidden = false;

    const summary = document.getElementById("compose-summary");
    clear(summary);
    keyValue(
      summary,
      "compose.result.carriers",
      response.carriers_applied.map((id) => t("carrier." + id + ".name")).join(", ")
    );
    keyValue(
      summary,
      "compose.result.cipher",
      response.sealed_to_recipient
        ? t("compose.result.recipient")
        : response.cipher
        ? t("cipher." + response.cipher + ".name")
        : t("cipher.none.name")
    );
    keyValue(
      summary,
      "compose.result.used",
      fmtInt(response.layer_bits) + " " + t("compose.capacity.bits")
    );
    // The honest overlay: what the tool's own analyser sees on the exact
    // document just produced, never an estimate (COMPOSE-4).
    keyValue(summary, "compose.result.density", fmtPercent(response.noise_density || 0));
    keyValue(
      summary,
      "compose.result.verdict",
      t("analyze.verdict." + (VERDICT_KEYS[response.verdict] || response.verdict))
    );

    const warnings = document.getElementById("compose-warnings");
    clear(warnings);
    if (!response.cover_restored) {
      showCalloutKey(warnings, "danger", "compose.result.hint");
    }
    response.warnings.forEach((line) => {
      const box = el("div", "callout callout--warning");
      box.textContent = line;
      warnings.appendChild(box);
    });

    document.getElementById("compose-json").textContent = JSON.stringify(
      Object.assign({}, response, { stego_text: undefined }),
      null,
      2
    );
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* Conceal the secret INTO the loaded cover file and offer the marked file to
 * download in its own format. Progress shows in the control frame, then the
 * result summarises the carriers, cipher and measured sizes. This is the
 * zero-loss in-place path, never a conversion: a container, web or lowered
 * cover, an empty secret, a capacity shortfall, or a cipher with no passphrase
 * surfaces the engine's NAMED refusal in the message callout, never a silent
 * result. */
async function runComposeFile(held) {
  const message = document.getElementById("compose-message");
  const secret = document.getElementById("compose-secret").value;
  const cipher = document.getElementById("compose-cipher").value;
  const password = document.getElementById("compose-password").value;
  // The file path validates the same inputs as the text path, minus the cover:
  // the cover is the loaded file, so no cover-text check applies.
  if (!secret.trim()) {
    showCalloutKey(message, "warning", "compose.error.no_secret");
    return;
  }
  if (!selectedCarriers().length) {
    showCalloutKey(message, "warning", "compose.error.no_carrier");
    return;
  }
  if (cipher === "recipient_pqc") {
    // Recipient sealing is not yet wired into the in-place file path. Name the
    // limit rather than silently hiding an unsealed secret (invariant 2): the
    // text path carries the recipient flow today.
    showCalloutKey(message, "warning", "compose.recipient.file_unsupported");
    return;
  }
  if (cipher !== "none" && !password) {
    showCalloutKey(message, "warning", "compose.error.no_password");
    return;
  }

  clear(message);
  setStatus("status.working");
  setProgress("compose-progress", true);
  try {
    const response = await invoke("file_conceal", {
      request: {
        bytes: held.bytes,
        format: held.format,
        secret,
        carriers: selectedCarriers(),
        cipher: cipher === "none" ? null : cipher,
        password: password || null,
        saturate: state.saturate,
      },
    });
    clear(message);
    renderComposeFileResult(response, held);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("compose-result").hidden = true;
    document.getElementById("compose-download").hidden = true;
    composeFileDownload = null;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  } finally {
    setProgress("compose-progress", false);
  }
}

function renderComposeFileResult(response, held) {
  document.getElementById("compose-result").hidden = false;

  // Text-native results carry the marked text; show it in the existing output
  // field. A container would carry none, so nothing is fabricated (invariant 2).
  document.getElementById("compose-output").value = response.marked_text || "";

  const summary = document.getElementById("compose-summary");
  clear(summary);
  keyValue(
    summary,
    "compose.result.carriers",
    response.carriers.map((id) => t("carrier." + id + ".name")).join(", ")
  );
  keyValue(
    summary,
    "compose.result.cipher",
    response.cipher ? t("cipher." + response.cipher + ".name") : t("cipher.none.name")
  );
  const bytesUnit = t("compose.payload.bytes");
  keyValue(summary, "compose.result.file.source", fmtInt(response.source_len) + " " + bytesUnit);
  keyValue(summary, "compose.result.file.marked", fmtInt(response.marked_len) + " " + bytesUnit);
  keyValue(summary, "compose.result.file.secret", fmtInt(response.secret_len) + " " + bytesUnit);

  clear(document.getElementById("compose-warnings"));
  document.getElementById("compose-json").textContent = JSON.stringify(
    Object.assign({}, response, { bytes: undefined, marked_text: undefined }),
    null,
    2
  );

  // Hold the marked bytes and a download name derived from the cover file, then
  // reveal the download control. The bytes are the engine's real output.
  const downloadName = fileBaseName(held.name) + ".marked." + held.format;
  composeFileDownload = { bytes: response.bytes, name: downloadName };
  document.getElementById("compose-download").hidden = false;
}

/* Hand the marked file back to the operator to save. Reuses the Files tab's blob
 * download, so no network origin is touched and the CSP already allows it. */
function runComposeDownload() {
  if (!composeFileDownload) return;
  filesOfferDownload(composeFileDownload.bytes, composeFileDownload.name);
  setStatus("status.done");
}

function clearCompose() {
  // Reset the cover file-import first so the textarea is re-enabled before its
  // value is cleared, then drop any held marked file and hide its controls.
  if (composeCoverImport) composeCoverImport.reset();
  composeFileDownload = null;
  document.getElementById("compose-download").hidden = true;
  setProgress("compose-progress", false);
  ["compose-secret", "compose-cover", "compose-password", "compose-output"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  document.getElementById("compose-result").hidden = true;
  clear(document.getElementById("compose-message"));
  clear(document.getElementById("compose-warnings"));
  clear(document.getElementById("compose-mission-message"));
  clearComposePayload();
  state.requiredBits = null;
  state.density = null;
  refreshCapacity();
  paintCapacity();
  refreshMission();
}

async function copyFrom(elementId) {
  const value = document.getElementById(elementId).value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setStatus("status.copied");
  } catch (error) {
    setStatus("status.error");
  }
}

/* ─── Compose payload (file, compression) ──────────────────── */

/* Encode a byte array as base64 without a dependency, so a recovered file can
   be copied out of the interface. Built one character at a time, which is fine
   for the small files this tool accepts. */
function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/* Attach a chosen file to the text to hide, optionally making it smaller first.
   The file becomes part of the layer Compose hides, through the same path as
   typed text. Every size shown is measured by the engine, never asserted; an
   empty or over-large file surfaces the engine's named refusal. */
async function runComposeAttach() {
  const message = document.getElementById("compose-payload-message");
  const fileInput = document.getElementById("compose-payload-file");
  if (!fileInput.files || !fileInput.files.length) {
    showCalloutKey(message, "warning", "compose.payload.error.no_file");
    return;
  }
  const file = fileInput.files[0];
  const compress = document.getElementById("compose-payload-compress").checked;
  setStatus("status.working");
  try {
    const buffer = await file.arrayBuffer();
    let bytes = Array.from(new Uint8Array(buffer));
    const sizes = { filename: file.name, original: bytes.length, compressed: null, ratio: null };

    if (compress) {
      const smaller = await invoke("compress_payload", { data: bytes, level: null });
      bytes = smaller.compressed;
      sizes.original = smaller.original_bytes;
      sizes.compressed = smaller.compressed_bytes;
      sizes.ratio = smaller.ratio;
    }

    const response = await invoke("attach_payload", {
      text: document.getElementById("compose-secret").value,
      filename: file.name,
      data: bytes,
    });
    document.getElementById("compose-secret").value = response.text;
    clear(message);
    renderComposePayload(response, sizes);

    // The layer to hide changed, so any earlier measurement is stale.
    state.requiredBits = null;
    paintCapacity();
    refreshMission();
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderComposePayload(response, sizes) {
  document.getElementById("compose-payload-result").hidden = false;
  const bytesUnit = t("compose.payload.bytes");

  const summary = document.getElementById("compose-payload-summary");
  clear(summary);
  keyValue(summary, "compose.payload.result.filename", sizes.filename);
  keyValue(summary, "compose.payload.result.original", fmtInt(sizes.original) + " " + bytesUnit);
  if (sizes.compressed !== null && sizes.compressed !== undefined) {
    keyValue(summary, "compose.payload.result.compressed", fmtInt(sizes.compressed) + " " + bytesUnit);
    keyValue(summary, "compose.payload.result.ratio", fmtPercent(sizes.ratio || 0));
  }
  keyValue(summary, "compose.payload.result.attached", fmtInt(response.attached_bytes) + " " + bytesUnit);
  keyValue(
    summary,
    "compose.payload.result.chars",
    fmtInt(response.chars_after) + " " + t("compose.payload.chars_unit")
  );

  showCalloutKey(document.getElementById("compose-payload-note"), "info", "compose.payload.result.note");
}

function clearComposePayload() {
  document.getElementById("compose-payload-file").value = "";
  document.getElementById("compose-payload-compress").checked = false;
  document.getElementById("compose-payload-result").hidden = true;
  clear(document.getElementById("compose-payload-message"));
  clear(document.getElementById("compose-payload-note"));
}

/* ─── Decode ───────────────────────────────────────────────── */

/* The reusable file-import handle for the received input, and the hidden file
 * held for download after a file decode recovered one. Both are set when Decode
 * runs on a loaded marked file, and reset when the input drops back to text or
 * is cleared. The text path never touches either. */
let decodeFileImport = null;
let decodeFileDownload = null;

async function runDecode() {
  // The file-import decides the path: a loaded marked file is decoded through
  // the file command, the same way Analyze routes a loaded file. With no file,
  // the pasted received-text path below is unchanged. The two paths stay cleanly
  // separated.
  const held = decodeFileImport ? decodeFileImport.get() : null;
  if (held) {
    await runDecodeFile(held);
    return;
  }

  const message = document.getElementById("decode-message");
  // The text path never offers a file download; hide any left by a file run.
  decodeFileDownload = null;
  document.getElementById("decode-download").hidden = true;

  const text = document.getElementById("decode-text").value;
  if (!text.trim()) {
    showCalloutKey(message, "warning", "decode.error.no_text");
    return;
  }
  const carrier = document.getElementById("decode-carrier").value;
  const password = document.getElementById("decode-password").value;
  const secretKey = document.getElementById("decode-secret-key").value.trim();
  setStatus("status.working");

  try {
    // A recipient secret key opens a payload sealed to you; without one the
    // recovered layer is returned as extracted. A wrong key is refused by name
    // by the backend and surfaces in the message callout.
    const response = secretKey
      ? await invoke("reveal_sealed", {
          text,
          carrier: carrier || null,
          recipient_secret_key: secretKey,
        })
      : await invoke("reveal", {
          text,
          carrier: carrier || null,
          password: password || null,
        });
    clear(message);
    renderDecodeResult(response);
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* Decode a loaded marked file: read its bytes through the file command, which
 * extracts the document's text and runs the SAME core reveal path the text path
 * runs, then render the identical result. When the recovered layer carries a
 * hidden file, offer it to download. Progress shows in the input frame while it
 * works. An unreadable or unsupported file, or a file with no recoverable layer,
 * surfaces the engine's NAMED refusal in the message callout, never a silent
 * empty result (invariant 2). */
async function runDecodeFile(held) {
  const message = document.getElementById("decode-message");
  // A file needs no pasted text; the carrier and passphrase controls still apply,
  // resolved exactly as the text path resolves them.
  const carrier = document.getElementById("decode-carrier").value;
  const password = document.getElementById("decode-password").value;
  const secretKey = document.getElementById("decode-secret-key").value.trim();
  if (secretKey) {
    // Recipient opening is not yet wired into the file decode path. Name the
    // limit rather than returning the sealed blob as if it were the secret
    // (invariant 2): paste the marked text to open a sealed payload today.
    showCalloutKey(message, "warning", "decode.recipient.file_unsupported");
    return;
  }
  decodeFileDownload = null;
  document.getElementById("decode-download").hidden = true;
  clear(message);
  setStatus("status.working");
  setProgress("decode-progress", true);
  try {
    const response = await invoke("file_decode", {
      request: {
        bytes: held.bytes,
        format: held.format,
        password: password || null,
        carrier: carrier || null,
      },
    });
    clear(message);
    renderDecodeResult(response);
    // If the recovered layer carries an attached file, offer it to download.
    await offerDecodedFile(response);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("decode-result").hidden = true;
    document.getElementById("decode-download").hidden = true;
    decodeFileDownload = null;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  } finally {
    setProgress("decode-progress", false);
  }
}

/* Render a reveal response into the result area. Shared by the text and file
 * paths so a file's decode renders exactly as a pasted text's: recovered layer,
 * carrier, cipher, payload size, and the integrity verdict. */
function renderDecodeResult(response) {
  document.getElementById("decode-result").hidden = false;
  document.getElementById("decode-output").value = response.hidden_text || "";

  const summary = document.getElementById("decode-summary");
  clear(summary);
  keyValue(
    summary,
    "decode.result.carriers",
    response.carriers_detected.map((id) => t("carrier." + id + ".name")).join(", ")
  );
  keyValue(
    summary,
    "decode.result.cipher",
    response.opened_for_recipient
      ? t("decode.result.recipient")
      : response.cipher_used
      ? t("cipher." + response.cipher_used + ".name")
      : t("decode.result.cipher_none")
  );
  keyValue(
    summary,
    "analyze.signatures.payload",
    fmtInt(response.hidden_size_bytes) + " " + t("analyze.signatures.bytes")
  );

  const warnings = document.getElementById("decode-warnings");
  clear(warnings);
  showCalloutKey(
    warnings,
    response.integrity ? "success" : "danger",
    response.integrity ? "decode.result.integrity_ok" : "decode.result.integrity_failed"
  );
  response.warnings.forEach((line) => {
    const box = el("div", "callout");
    box.textContent = line;
    warnings.appendChild(box);
  });

  document.getElementById("decode-json").textContent = JSON.stringify(response, null, 2);
}

/* When a recovered layer is text that carries an attached file, hand the file
 * back to save. Reuses the existing recover path (recover_attachments) and the
 * Files blob helper; the bytes are the engine's real output, never fabricated. A
 * binary layer, or a layer carrying no file, leaves the download hidden. */
async function offerDecodedFile(response) {
  if (!response.hidden_text) return;
  let recovered;
  try {
    recovered = await invoke("recover_attachments", { text: response.hidden_text });
  } catch (error) {
    return;
  }
  if (!recovered.count || !recovered.files.length) return;
  const file = recovered.files[0];
  decodeFileDownload = { bytes: file.data, name: file.filename };
  document.getElementById("decode-download").hidden = false;
}

/* Hand the recovered hidden file back to the operator to save. Reuses the Files
 * tab's blob download, so no network origin is touched and the CSP already
 * allows it. */
function runDecodeDownload() {
  if (!decodeFileDownload) return;
  filesOfferDownload(decodeFileDownload.bytes, decodeFileDownload.name);
  setStatus("status.done");
}

/* Resolve a panel's subject from either its textarea or a picked document file.
 * A picked file's bytes are read and its text extracted through document_text, so
 * every panel accepts a real document as uniformly as pasted text. A picked file
 * takes precedence over the textarea. */
async function resolveTextOrFile(textareaId, fileInputId) {
  const fileInput = document.getElementById(fileInputId);
  const file = fileInput && fileInput.files && fileInput.files[0];
  if (file) {
    const buffer = await file.arrayBuffer();
    const bytes = Array.from(new Uint8Array(buffer));
    const format = file.name.split(".").pop() || "";
    return await invoke("document_text", { bytes, format });
  }
  return document.getElementById(textareaId).value;
}

/* Resolve a panel's subject, surfacing an extraction failure in the panel's own
 * message area and returning null so the caller can stop. A file that carries no
 * readable text (an image) is named, never silently treated as empty. */
/* True when a file has been picked in the given file input, so a validator can
 * accept a file standing in for an empty textarea. */
function hasFile(fileInputId) {
  const input = document.getElementById(fileInputId);
  return Boolean(input && input.files && input.files[0]);
}

async function subjectOrFail(textareaId, fileInputId, message) {
  try {
    return await resolveTextOrFile(textareaId, fileInputId);
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return null;
  }
}

/* Fill every result panel's export picker from the shared format set, so all
 * panels export to the same formats. The option text is the format extension, a
 * language-neutral identifier; the picker defaults to txt, which is byte-faithful
 * so a marked cover's hidden layer survives the export. */
function renderExportSelects() {
  [
    "compose-export-format",
    "decode-export-format",
    "airegulation-clean-export-format",
    "airegulation-pristine-export-format",
    "airegulation-wm-scrub-export-format",
    "airegulation-wm-rewrite-export-format",
    "decoder-export-format",
    "mark-marked-export-format",
  ].forEach((id) => {
    const select = document.getElementById(id);
    if (!select) return;
    clear(select);
    state.exportFormats.forEach((ext) => {
      const option = el("option");
      option.value = ext;
      option.textContent = ext.toUpperCase();
      select.appendChild(option);
    });
    if (state.exportFormats.includes("txt")) select.value = "txt";
  });
}

/* Export a result panel's text to the chosen format and hand the file back to
 * save, so every result is downloadable as well as copyable. A refusal (an empty
 * result, an unknown or unwritable target) surfaces in the panel's message area,
 * never a silent no-op (invariant 2). */
async function runExport(outputId, baseName, formatSelectId, messageId) {
  const text = document.getElementById(outputId).value;
  const message = document.getElementById(messageId);
  if (!text) {
    showCalloutKey(message, "warning", "export.error.empty");
    return;
  }
  const target = document.getElementById(formatSelectId).value;
  setStatus("status.working");
  try {
    const bytes = await invoke("export_result", { text, target });
    filesOfferDownload(bytes, `${baseName}.${target}`);
    clear(message);
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* Read the live MCP setup picture and paint the Rest/mcp tab: the resolved
 * stegano-mcp command, the universal snippet, the REST base URL, and every known
 * client with whether it is present and whether the app can configure it. */
async function renderRestMcp() {
  let info;
  try {
    info = await invoke("mcp_setup_info");
  } catch (error) {
    showCallout(document.getElementById("restmcp-message"), "danger", describeError(error));
    return;
  }
  state.mcpInfo = info;

  const summary = document.getElementById("restmcp-summary");
  clear(summary);
  keyValue(summary, "restmcp.server.command", info.server_command);
  keyValue(
    summary,
    "restmcp.server.location",
    t(info.bundled ? "restmcp.server.bundled" : "restmcp.server.on_path")
  );
  document.getElementById("restmcp-snippet").value = info.json_snippet;

  const rest = document.getElementById("restmcp-rest");
  clear(rest);
  keyValue(rest, "restmcp.rest.base", info.rest_base_url);
  keyValue(rest, "restmcp.rest.tools", info.rest_base_url + "/tools");

  const list = document.getElementById("restmcp-clients");
  clear(list);
  info.clients.forEach((client) => {
    const row = el("div", "mcp-client");
    const head = el("div", "mcp-client-head");
    const name = el("span", "mcp-client-name");
    name.textContent = client.label;
    head.appendChild(name);
    const badge = el("span", "badge");
    setText(badge, client.detected ? "restmcp.client.detected" : "restmcp.client.not_detected");
    head.appendChild(badge);
    const mode = el("span", "mcp-client-mode");
    setText(mode, client.writable ? "restmcp.client.auto" : "restmcp.client.manual");
    head.appendChild(mode);
    row.appendChild(head);
    const path = el("div", "mcp-client-path");
    path.textContent = client.config_path;
    row.appendChild(path);
    // A client this app cannot write safely shows the exact snippet to paste.
    if (!client.writable && client.snippet) {
      const snippet = el("textarea", "is-output");
      snippet.readOnly = true;
      snippet.rows = 3;
      snippet.value = client.snippet;
      row.appendChild(snippet);
    }
    list.appendChild(row);
  });
}

/* Configure every writable, detected client in one click. Each config file is
 * backed up and merged, never overwritten; the outcome of each is shown. */
async function runRestMcpConfigure() {
  const message = document.getElementById("restmcp-message");
  const info = state.mcpInfo;
  if (!info) return;
  const ids = info.clients.filter((client) => client.writable && client.detected).map((client) => client.id);
  if (!ids.length) {
    showCalloutKey(message, "warning", "restmcp.none_detected");
    return;
  }
  setStatus("status.working");
  try {
    const outcomes = await invoke("mcp_configure", { clientIds: ids });
    clear(message);
    outcomes.forEach((outcome) => {
      const level =
        outcome.status === "configured" || outcome.status === "already_present"
          ? "success"
          : outcome.status === "error"
          ? "danger"
          : "info";
      const box = el("div", "callout callout--" + level);
      box.textContent = `${outcome.label}: ${t("restmcp.status." + outcome.status)} (${outcome.detail})`;
      message.appendChild(box);
    });
    setStatus("status.done");
    // Re-read so the detected state and any new config reflect what just changed.
    renderRestMcp();
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* Generate a recipient keypair and show both halves. The public half is what a
 * sender pastes into Compose's recipient mode; the secret half opens what was
 * sealed to you. This surface keeps neither half: they live only in these
 * fields until the operator copies them out. */
async function runPqcKeypair() {
  const message = document.getElementById("decode-message");
  setStatus("status.working");
  try {
    const keypair = await invoke("pqc_keypair");
    document.getElementById("decode-keypair-public").value = keypair.public_key;
    document.getElementById("decode-keypair-secret").value = keypair.secret_key;
    document.getElementById("decode-keypair-result").hidden = false;
    clear(message);
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function clearDecode() {
  // Reset the file-import first so the textarea is re-enabled before its value is
  // cleared, then drop any held recovered file and hide its controls.
  if (decodeFileImport) decodeFileImport.reset();
  decodeFileDownload = null;
  document.getElementById("decode-download").hidden = true;
  setProgress("decode-progress", false);
  ["decode-text", "decode-password", "decode-secret-key", "decode-output"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  document.getElementById("decode-result").hidden = true;
  clear(document.getElementById("decode-message"));
  clear(document.getElementById("decode-warnings"));
}

/* ─── Recover a hidden file (backlog UI-payload) ───────────── */

/* List the files a text carries and read them back. Reports what is there,
   never a guess: a text with no attached file says so. */
async function runRecoverAttachments() {
  const message = document.getElementById("decode-recover-message");
  const text = document.getElementById("decode-recover-text").value;
  if (!text.trim()) {
    showCalloutKey(message, "warning", "decode.recover.error.no_text");
    return;
  }
  setStatus("status.working");
  try {
    const response = await invoke("recover_attachments", { text });
    clear(message);
    renderRecoverAttachments(response);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("decode-recover-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderRecoverAttachments(response) {
  document.getElementById("decode-recover-result").hidden = false;

  const verdict = document.getElementById("decode-recover-verdict");
  clear(verdict);
  if (!response.count) {
    showCalloutKey(verdict, "info", "decode.recover.result.none");
  } else {
    showCallout(verdict, "success", t("decode.recover.result.count") + " " + fmtInt(response.count));
  }

  const host = document.getElementById("decode-recover-files");
  clear(host);
  response.files.forEach((file) => host.appendChild(renderRecoveredFile(file)));
}

function renderRecoveredFile(file) {
  const card = el("div", "signature");

  const head = el("div", "signature-head");
  const name = el("span", "signature-name");
  name.textContent = file.filename;
  head.appendChild(name);

  const size = el("span", "badge");
  size.textContent = fmtInt(file.byte_count) + " " + t("decode.recover.file.bytes");
  head.appendChild(size);

  const actions = el("div", "card-actions");
  const copy = el("button", "btn btn--small");
  copy.type = "button";
  setText(copy, "decode.recover.file.copy");
  copy.addEventListener("click", () => copyText(bytesToBase64(file.data)));
  actions.appendChild(copy);

  const note = el("div", "signature-detail");

  const expand = el("button", "btn btn--small");
  expand.type = "button";
  setText(expand, "decode.recover.file.expand");
  expand.addEventListener("click", () => runExpandFile(file, note));
  actions.appendChild(expand);

  head.appendChild(actions);
  card.appendChild(head);
  card.appendChild(note);
  return card;
}

/* Restore a file that was made smaller before hiding. When the file was not
   made smaller, the engine refuses by name and the refusal is shown as it is. */
async function runExpandFile(file, note) {
  setStatus("status.working");
  try {
    const response = await invoke("expand_payload", { compressed: file.data });
    clear(note);
    note.textContent = t("decode.recover.expanded").replace("{bytes}", fmtInt(response.byte_count));
    setStatus("status.done");
  } catch (error) {
    clear(note);
    note.textContent = describeError(error);
    setStatus("status.error");
  }
}

function clearRecoverAttachments() {
  document.getElementById("decode-recover-text").value = "";
  document.getElementById("decode-recover-result").hidden = true;
  clear(document.getElementById("decode-recover-message"));
  clear(document.getElementById("decode-recover-files"));
}

/* ─── Analyze ──────────────────────────────────────────────── */

/* Four distinct badges on an ascending severity gradient. Suspicious ("could
   be legitimate") reads as a neutral notice, not the same weight as Modified
   ("strong evidence"), so the badge never overstates what the verdict means. */
const VERDICT_STYLE = {
  Clean: "badge--success",
  Suspicious: "badge--info",
  Modified: "badge--warning",
  Confirmed: "badge--danger",
};

const VERDICT_NOTE = {
  Clean: "analyze.verdict.clean_note",
  Suspicious: "analyze.verdict.suspicious_note",
  Modified: "analyze.verdict.modified_note",
  Confirmed: "analyze.verdict.confirmed_note",
};

function renderSignatures(report) {
  const host = document.getElementById("analyze-signatures");
  clear(host);
  if (!report.stego_signatures.length) {
    showCalloutKey(host, "", "analyze.signatures.empty");
    return;
  }
  report.stego_signatures.forEach((signature) => {
    const card = el("div", "signature");
    const head = el("div", "signature-head");

    const name = el("span", "signature-name");
    name.textContent = t("carrier." + signature.method + ".name");
    head.appendChild(name);

    const confidence = el("span", "badge");
    confidence.textContent = t("analyze.signatures.confidence") + " " +
      fmtPercent(signature.confidence);
    head.appendChild(confidence);

    const readable = el("span", signature.decodable ? "badge badge--danger" : "badge");
    setText(readable, signature.decodable
      ? "analyze.signatures.decodable_yes"
      : "analyze.signatures.decodable_no");
    head.appendChild(readable);

    if (signature.estimated_payload_bytes !== null &&
        signature.estimated_payload_bytes !== undefined) {
      const size = el("span", "badge");
      size.textContent = t("analyze.signatures.payload") + " " +
        fmtInt(signature.estimated_payload_bytes) + " " + t("analyze.signatures.bytes");
      head.appendChild(size);
    }

    const detail = el("div", "signature-detail");
    detail.textContent = signature.detail;

    card.appendChild(head);
    card.appendChild(detail);
    host.appendChild(card);
  });
}

function renderTable(host, headerKeys, rows) {
  clear(host);
  const scroll = el("div", "table-scroll");
  const table = el("table");
  const thead = el("thead");
  const headRow = el("tr");
  headerKeys.forEach((key) => {
    const cell = el("th");
    setText(cell, key);
    headRow.appendChild(cell);
  });
  thead.appendChild(headRow);
  const tbody = el("tbody");
  rows.forEach((row) => {
    const tr = el("tr");
    row.forEach((value) => {
      const td = el("td", "is-mono");
      td.textContent = value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(thead);
  table.appendChild(tbody);
  scroll.appendChild(table);
  host.appendChild(scroll);
}

function renderUnicode(report) {
  const unicode = report.unicode_analysis;

  const counts = document.getElementById("analyze-unicode-counts");
  clear(counts);
  keyValue(counts, "analyze.unicode.total", fmtInt(unicode.total_chars));
  keyValue(counts, "analyze.unicode.visible", fmtInt(unicode.visible_chars));
  keyValue(counts, "analyze.unicode.invisible", fmtInt(unicode.invisible_chars));
  keyValue(counts, "analyze.unicode.bidi_controls", fmtInt(unicode.bidi_controls));

  const breakdown = document.getElementById("analyze-unicode-breakdown");
  const entries = Object.entries(unicode.invisible_breakdown || {});
  if (!entries.length) {
    showCalloutKey(breakdown, "", "analyze.unicode.breakdown_empty");
  } else {
    renderTable(
      breakdown,
      ["analyze.unicode.column_codepoint", "analyze.unicode.column_count"],
      entries.map(([name, count]) => [name, fmtInt(count)])
    );
  }

  const scripts = document.getElementById("analyze-unicode-scripts");
  if (!unicode.mixed_scripts.length) {
    showCalloutKey(scripts, "", "analyze.unicode.scripts_empty");
  } else {
    renderTable(
      scripts,
      [
        "analyze.unicode.script_primary",
        "analyze.unicode.script_secondary",
        "analyze.unicode.script_count",
        "analyze.unicode.script_pattern",
      ],
      unicode.mixed_scripts.map((mix) => [
        mix.primary,
        mix.secondary,
        fmtInt(mix.secondary_count),
        mix.pattern,
      ])
    );
  }

  const unusual = document.getElementById("analyze-unicode-unusual");
  if (!unicode.unusual_categories.length) {
    showCalloutKey(unusual, "", "analyze.unicode.unusual_empty");
  } else {
    renderTable(
      unusual,
      [
        "analyze.unicode.column_codepoint",
        "analyze.unicode.column_category",
        "analyze.unicode.column_count",
      ],
      unicode.unusual_categories.map((entry) => [
        entry.codepoint,
        entry.category,
        fmtInt(entry.count),
      ])
    );
  }
}

/* ─── Reusable file-import, progress and export ────────────────
 *
 * The pieces this slice introduces once, so any function that reads a text
 * input can also accept a file, show it working, and export its report. Each
 * is generic on element ids, so another tab (Compose, Decode) wires its own
 * input by naming that tab's elements.
 */

/* Wire a textarea and its paired file input so a picked or dropped file becomes
 * the input. When a file is chosen its bytes are read and held, and an overlay
 * over the textarea shows the file name and extension with a control to drop
 * back to text entry. While a file is held the caller reads it through the
 * returned handle and ignores the textarea's own text. Returns a handle whose
 * get() yields { bytes, name, format } or null, and whose reset() clears it.
 */
function wireFileImport(config) {
  const textarea = document.getElementById(config.textareaId);
  const fileInput = document.getElementById(config.fileInputId);
  const frame = document.getElementById(config.frameId);
  const overlay = document.getElementById(config.overlayId);
  const nameNode = document.getElementById(config.nameId);
  const extNode = document.getElementById(config.extId);
  const removeButton = document.getElementById(config.removeId);

  /* The loaded file, or null while the input is on the text path. */
  let held = null;

  function paint() {
    if (held) {
      nameNode.textContent = held.name;
      extNode.textContent = held.format ? "." + held.format : "";
      extNode.hidden = !held.format;
      overlay.hidden = false;
      textarea.disabled = true;
    } else {
      nameNode.textContent = "";
      extNode.textContent = "";
      overlay.hidden = true;
      textarea.disabled = false;
    }
  }

  async function load(file) {
    const buffer = await file.arrayBuffer();
    held = {
      bytes: Array.from(new Uint8Array(buffer)),
      name: file.name,
      format: fileExtension(file.name),
    };
    paint();
    if (config.onChange) config.onChange();
  }

  function reset() {
    held = null;
    fileInput.value = "";
    frame.removeAttribute("data-dragover");
    paint();
  }

  function accept(file) {
    load(file).catch((error) => {
      reset();
      if (config.onError) config.onError(error);
    });
  }

  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files.length) accept(fileInput.files[0]);
  });
  removeButton.addEventListener("click", () => {
    reset();
    if (config.onChange) config.onChange();
  });

  ["dragenter", "dragover"].forEach((type) => {
    frame.addEventListener(type, (event) => {
      event.preventDefault();
      frame.setAttribute("data-dragover", "true");
    });
  });
  ["dragleave", "dragend"].forEach((type) => {
    frame.addEventListener(type, () => frame.removeAttribute("data-dragover"));
  });
  frame.addEventListener("drop", (event) => {
    event.preventDefault();
    frame.removeAttribute("data-dragover");
    const files = event.dataTransfer && event.dataTransfer.files;
    if (files && files.length) accept(files[0]);
  });

  paint();
  return { get: () => held, reset };
}

/* Show or hide the indeterminate progress bar of an output frame while it
 * works. The bar itself lives in the markup; this only toggles it. */
function setProgress(progressId, active) {
  document.getElementById(progressId).hidden = !active;
}

/* Offer a report object to the operator as a downloadable JSON file, named
 * from the source, through an object URL. No network origin is touched, and
 * the CSP already allows blob URLs. Reused by any analyser output frame. */
function offerReportDownload(report, filename) {
  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = el("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

/* ─── Analyze ──────────────────────────────────────────────────
 *
 * The reference application of the file-import pattern above: the input frame
 * accepts a file, the output shows progress then the report, and the report
 * exports. The file handle and the last report are held so the export control
 * and the file/text branch can read them. */
let analyzeFileImport = null;
let analyzeLastReport = null;
let analyzeReportName = "report.json";

async function runAnalyze() {
  const message = document.getElementById("analyze-message");
  const held = analyzeFileImport ? analyzeFileImport.get() : null;
  const text = document.getElementById("analyze-text").value;
  // A loaded file becomes the input: its bytes are analysed and the textarea's
  // own text is ignored. With no file, the pasted text is the input.
  if (!held && !text.trim()) {
    showCalloutKey(message, "warning", "analyze.error.no_text");
    return;
  }
  clear(message);
  setStatus("status.working");
  setProgress("analyze-progress", true);

  try {
    const report = held
      ? await invoke("file_analyze", { request: { bytes: held.bytes, format: held.format } })
      : await invoke("forensic_analyze", { text });
    clear(message);

    ["analyze-verdict-card", "analyze-signatures-card", "analyze-unicode-card",
      "analyze-stats-card"].forEach((id) => {
      document.getElementById(id).hidden = false;
    });

    const badge = document.getElementById("analyze-verdict-badge");
    badge.className = "badge " + (VERDICT_STYLE[report.verdict] || "");
    setText(badge, "analyze.verdict." + report.verdict);
    setText(document.getElementById("analyze-verdict-note"),
      VERDICT_NOTE[report.verdict] || "analyze.verdict.label");
    document.getElementById("analyze-score").textContent = fmtPercent(report.suspicion_score);

    const summary = document.getElementById("analyze-summary");
    clear(summary);
    report.summary.forEach((line) => {
      const item = el("li");
      item.textContent = line;
      summary.appendChild(item);
    });

    renderSignatures(report);
    renderUnicode(report);

    const stats = document.getElementById("analyze-stats");
    clear(stats);
    keyValue(stats, "analyze.stats.entropy",
      fmtFixed(report.statistics.shannon_entropy, 3) + " " + t("analyze.stats.entropy_unit"));
    keyValue(stats, "analyze.stats.noise_density",
      fmtPercent(report.statistics.noise_density));
    keyValue(stats, "analyze.stats.homoglyph_density",
      fmtPercent(report.statistics.homoglyph_density));
    keyValue(stats, "analyze.stats.assessment", report.statistics.entropy_assessment);

    document.getElementById("analyze-json").textContent = JSON.stringify(report, null, 2);

    // The report can now be exported, named from the source when a file drove
    // the analysis, or a plain report name for a pasted text.
    analyzeLastReport = report;
    analyzeReportName = held ? fileBaseName(held.name) + ".report.json" : "report.json";
    document.getElementById("analyze-export").hidden = false;
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  } finally {
    setProgress("analyze-progress", false);
  }
}

function runAnalyzeExport() {
  if (!analyzeLastReport) return;
  offerReportDownload(analyzeLastReport, analyzeReportName);
}

function clearAnalyze() {
  document.getElementById("analyze-text").value = "";
  if (analyzeFileImport) analyzeFileImport.reset();
  analyzeLastReport = null;
  document.getElementById("analyze-export").hidden = true;
  setProgress("analyze-progress", false);
  clear(document.getElementById("analyze-message"));
  ["analyze-verdict-card", "analyze-signatures-card", "analyze-unicode-card",
    "analyze-stats-card"].forEach((id) => {
    document.getElementById(id).hidden = true;
  });
}

async function runCompare() {
  const message = document.getElementById("compare-message");
  const original = document.getElementById("compare-original").value;
  const candidate = document.getElementById("compare-candidate").value;
  if (!original.trim() || !candidate.trim()) {
    showCalloutKey(message, "warning", "analyze.error.no_pair");
    return;
  }
  setStatus("status.working");
  try {
    const result = await invoke("compute_metrics", { original, candidate });
    clear(message);
    const host = document.getElementById("compare-result");
    host.hidden = false;
    clear(host);
    keyValue(host, "analyze.compare.shannon", fmtFixed(result.shannon_delta, 4));
    keyValue(host, "analyze.compare.noise", fmtPercent(result.noise_density));
    keyValue(host, "analyze.compare.perplexity", fmtFixed(result.perplexity_delta, 4));
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* ─── Provenance ───────────────────────────────────────────── */

function renderBindingOptions() {
  const select = document.getElementById("mark-binding");
  const previous = select.value;
  clear(select);
  BINDING_IDS.forEach((id) => {
    const option = el("option");
    option.value = id;
    setText(option, "provenance.binding." + id + ".name");
    select.appendChild(option);
  });
  select.value = previous || BINDING_IDS[0];
  if (!select.value) select.value = BINDING_IDS[0];
  paintBindingNote();
}

function paintBindingNote() {
  const select = document.getElementById("mark-binding");
  setText(document.getElementById("mark-binding-note"), "provenance.binding." + select.value + ".note");
  document.getElementById("mark-carrier-field").hidden = select.value !== "in_band";
}

function renderMarkCarrierOptions() {
  const select = document.getElementById("mark-carrier");
  const previous = select.value;
  clear(select);
  state.carriers.forEach((id) => {
    const option = el("option");
    option.value = id;
    setText(option, "carrier." + id + ".name");
    select.appendChild(option);
  });
  select.value = previous || (state.carriers.length ? state.carriers[0] : "");
}

/* Carriers to try an in-band read through. Rendered as checkboxes, all checked
   by default, so a received text is read through every carrier unless narrowed. */
function renderVerifyCarrierChips() {
  const grid = document.getElementById("verify-carriers");
  const previous = new Set(selectedVerifyCarriers());
  const seen = grid.querySelector("input");
  clear(grid);
  state.carriers.forEach((id) => {
    const chip = el("label", "chip");
    const box = el("input");
    box.type = "checkbox";
    box.value = id;
    box.checked = seen ? previous.has(id) : true;
    chip.setAttribute("data-checked", box.checked ? "true" : "false");
    box.addEventListener("change", () => {
      chip.setAttribute("data-checked", box.checked ? "true" : "false");
    });
    const body = el("div");
    const name = el("div", "chip-name");
    setText(name, "carrier." + id + ".name");
    body.appendChild(name);
    chip.appendChild(box);
    chip.appendChild(body);
    grid.appendChild(chip);
  });
}

function selectedVerifyCarriers() {
  return Array.from(document.querySelectorAll("#verify-carriers input[type=checkbox]"))
    .filter((box) => box.checked)
    .map((box) => box.value);
}

/* Reveal an assertion's own fields only while that assertion is selected. */
function syncAssertionFields() {
  document.getElementById("assert-human-fields").hidden =
    !document.getElementById("assert-human").checked;
  document.getElementById("assert-ai-fields").hidden =
    !document.getElementById("assert-ai").checked;
  document.getElementById("assert-recipient-fields").hidden =
    !document.getElementById("assert-recipient").checked;
}

async function runGenerateIdentity() {
  setStatus("status.working");
  try {
    const identity = await invoke("generate_signing_identity");
    const summary = document.getElementById("identity-summary");
    clear(summary);
    keyValue(summary, "provenance.identity.algorithm", identity.algorithm);
    document.getElementById("identity-public").value = identity.public_key;
    document.getElementById("identity-private").value = identity.private_key;
    document.getElementById("identity-result").hidden = false;
    setStatus("status.done");
  } catch (error) {
    setStatus("status.error");
  }
}

function markValidationKey() {
  if (!document.getElementById("mark-document").value.trim() && !hasFile("mark-document-file")) {
    return "provenance.mark.error.no_document";
  }
  const anyAssertion = ["assert-human", "assert-ai", "assert-integrity", "assert-recipient"]
    .some((id) => document.getElementById(id).checked);
  if (!anyAssertion) return "provenance.mark.error.no_assertion";
  if (!document.getElementById("mark-key").value.trim()) return "provenance.mark.error.no_key";
  if (document.getElementById("mark-binding").value === "in_band" &&
      !document.getElementById("mark-carrier").value) {
    return "provenance.mark.error.no_carrier";
  }
  return null;
}

function markAssertionsFromForm() {
  const value = (id) => {
    const text = document.getElementById(id).value.trim();
    return text ? text : null;
  };
  return {
    human_authorship: document.getElementById("assert-human").checked,
    author: value("mark-author"),
    ai_generated: document.getElementById("assert-ai").checked,
    model: value("mark-model"),
    provider: value("mark-provider"),
    system_version: value("mark-system-version"),
    integrity: document.getElementById("assert-integrity").checked,
    recipient_fingerprint: document.getElementById("assert-recipient").checked,
    recipient_id: value("mark-recipient-id"),
    recipient_salt: value("mark-recipient-salt"),
  };
}

function robustnessLine(container, labelKey, robustness) {
  const item = keyValue(container, labelKey, t(ROBUSTNESS_KEY[robustness.class] || robustness.class));
  const note = el("div", "field-hint");
  note.textContent = robustness.note;
  item.appendChild(note);
}

async function runMark() {
  const message = document.getElementById("mark-message");
  const problem = markValidationKey();
  if (problem) {
    showCalloutKey(message, "warning", problem);
    return;
  }
  const cover = await subjectOrFail("mark-document", "mark-document-file", message);
  if (cover === null) return;
  const binding = document.getElementById("mark-binding").value;
  const request = {
    cover,
    assertions: markAssertionsFromForm(),
    private_key: document.getElementById("mark-key").value.trim(),
    binding,
    carrier: binding === "in_band" ? document.getElementById("mark-carrier").value : null,
    created: document.getElementById("mark-timestamp").checked ? new Date().toISOString() : null,
  };
  setStatus("status.working");
  try {
    const response = await invoke("provenance_mark", { request });
    clear(message);
    renderMarkResult(response);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("mark-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderMarkResult(response) {
  document.getElementById("mark-result").hidden = false;

  const restored = document.getElementById("mark-cover-restored");
  clear(restored);
  if (response.cover_restored === false) {
    showCalloutKey(restored, "danger", "provenance.mark.result.cover_restored_failed");
  } else if (response.cover_restored === true) {
    showCalloutKey(restored, "success", "provenance.mark.result.cover_restored_ok");
  }

  const sidecarField = document.getElementById("mark-sidecar-field");
  if (response.sidecar) {
    document.getElementById("mark-sidecar").value = response.sidecar;
    sidecarField.hidden = false;
  } else {
    sidecarField.hidden = true;
  }

  const markedField = document.getElementById("mark-marked-field");
  if (response.marked_text) {
    document.getElementById("mark-marked").value = response.marked_text;
    markedField.hidden = false;
  } else {
    markedField.hidden = true;
  }

  const summary = document.getElementById("mark-summary");
  clear(summary);
  keyValue(summary, "provenance.mark.result.assertions",
    response.assertion_kinds.map((kind) => t("provenance.assertion." + kind + ".name")).join(", "));
  keyValue(summary, "provenance.mark.result.signer", response.signer_public_key);
  robustnessLine(summary, "provenance.mark.result.declared", response.declared_robustness);
  if (response.measured_robustness) {
    robustnessLine(summary, "provenance.mark.result.measured", response.measured_robustness);
  }

  document.getElementById("mark-json").textContent = JSON.stringify(
    Object.assign({}, response, { sidecar: undefined, marked_text: undefined }),
    null,
    2
  );
}

function clearMark() {
  ["mark-document", "mark-author", "mark-model", "mark-provider", "mark-system-version",
    "mark-recipient-id", "mark-recipient-salt", "mark-key", "mark-sidecar", "mark-marked"]
    .forEach((id) => { document.getElementById(id).value = ""; });
  ["assert-human", "assert-ai", "assert-integrity", "assert-recipient", "mark-timestamp"]
    .forEach((id) => { document.getElementById(id).checked = false; });
  syncAssertionFields();
  document.getElementById("mark-result").hidden = true;
  clear(document.getElementById("mark-message"));
}

async function runVerify() {
  const message = document.getElementById("verify-message");
  const document_ = await subjectOrFail("verify-document", "verify-document-file", message);
  if (document_ === null) return;
  if (!document_.trim()) {
    showCalloutKey(message, "warning", "provenance.verify.error.no_document");
    return;
  }
  const keys = document.getElementById("verify-keys").value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length);
  const request = {
    document: document_,
    sidecar: document.getElementById("verify-sidecar").value || null,
    trusted_keys: keys,
    carriers: selectedVerifyCarriers(),
  };
  setStatus("status.working");
  try {
    const report = await invoke("provenance_verify", { request });
    clear(message);
    renderVerifyReport(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("verify-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderVerifyReport(report) {
  document.getElementById("verify-result").hidden = false;
  const host = document.getElementById("verify-report");
  clear(host);

  if (!report.claims.length) {
    showCalloutKey(host, "info", "provenance.verify.result.none");
  } else {
    report.claims.forEach((claim, index) => {
      host.appendChild(renderVerifiedClaim(claim, index === report.strongest));
    });
  }

  if (report.unmet_requirements && report.unmet_requirements.length) {
    const card = el("div", "signature");
    const head = el("div", "signature-head");
    const title = el("span", "signature-name");
    setText(title, "provenance.verify.unmet.title");
    head.appendChild(title);
    card.appendChild(head);
    report.unmet_requirements.forEach((unmet) => {
      const line = el("div", "signature-detail");
      line.textContent = unmet.reason;
      card.appendChild(line);
    });
    host.appendChild(card);
  }

  document.getElementById("verify-json").textContent = JSON.stringify(report, null, 2);
}

function renderVerifiedClaim(claim, isStrongest) {
  const card = el("div", "signature");

  const head = el("div", "signature-head");
  const binding = el("span", "signature-name");
  binding.textContent = t("provenance.binding." + claim.binding + ".name");
  head.appendChild(binding);

  const signature = el("span", claim.signature_valid ? "badge badge--success" : "badge badge--danger");
  setText(signature, claim.signature_valid
    ? "provenance.verify.claim.signature_valid"
    : "provenance.verify.claim.signature_invalid");
  head.appendChild(signature);

  const altered = el("span", claim.document_unaltered ? "badge badge--success" : "badge badge--danger");
  setText(altered, claim.document_unaltered
    ? "provenance.verify.claim.document_unaltered"
    : "provenance.verify.claim.document_altered");
  head.appendChild(altered);

  const trusted = el("span", claim.signer_trusted ? "badge badge--success" : "badge badge--warning");
  setText(trusted, claim.signer_trusted
    ? "provenance.verify.claim.signer_trusted"
    : "provenance.verify.claim.signer_untrusted");
  head.appendChild(trusted);

  if (isStrongest) {
    const strongest = el("span", "badge badge--info");
    setText(strongest, "provenance.verify.result.strongest");
    head.appendChild(strongest);
  }
  card.appendChild(head);

  const kv = el("div", "kv");
  keyValue(kv, "provenance.verify.claim.assertions",
    claim.assertion_kinds.map((kind) => t("provenance.assertion." + kind + ".name")).join(", "));
  keyValue(kv, "provenance.verify.claim.signer", claim.signer.key);
  robustnessLine(kv, "provenance.verify.claim.robustness", claim.robustness_realised);
  card.appendChild(kv);

  claim.findings.forEach((finding) => {
    const line = el("div", "signature-detail");
    line.textContent = finding;
    card.appendChild(line);
  });

  return card;
}

function clearVerify() {
  ["verify-document", "verify-sidecar", "verify-keys"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  document.getElementById("verify-result").hidden = true;
  clear(document.getElementById("verify-message"));
}

/* ─── Canary ───────────────────────────────────────────────── */

/* Copy a raw string the interface holds in memory, distinct from copyFrom
   which reads the value out of an input element. */
async function copyText(value) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setStatus("status.copied");
  } catch (error) {
    setStatus("status.error");
  }
}

function canaryRecipients() {
  return document.getElementById("canary-recipients").value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length);
}

function canaryGenerateValidationKey() {
  if (!document.getElementById("canary-document").value.trim() && !hasFile("canary-document-file")) {
    return "canary.generate.error.no_document";
  }
  if (!canaryRecipients().length) return "canary.generate.error.no_recipients";
  if (!document.getElementById("canary-salt").value.trim()) {
    return "canary.generate.error.no_salt";
  }
  return null;
}

async function runCanaryGenerate() {
  const message = document.getElementById("canary-generate-message");
  const problem = canaryGenerateValidationKey();
  if (problem) {
    showCalloutKey(message, "warning", problem);
    return;
  }
  const documentText = await subjectOrFail("canary-document", "canary-document-file", message);
  if (documentText === null) return;
  const request = {
    document: documentText,
    recipients: canaryRecipients(),
    salt: document.getElementById("canary-salt").value.trim(),
  };
  setStatus("status.working");
  try {
    const response = await invoke("canary_generate", { request });
    clear(message);
    renderCanaryGenerate(response);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("canary-generate-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderCanaryGenerate(response) {
  document.getElementById("canary-generate-result").hidden = false;

  const restored = document.getElementById("canary-cover-restored");
  clear(restored);
  if (response.cover_restored) {
    showCalloutKey(restored, "success", "canary.generate.result.cover_restored_ok");
  } else {
    showCalloutKey(restored, "danger", "canary.generate.result.cover_restored_failed");
  }

  const summary = document.getElementById("canary-generate-summary");
  clear(summary);
  keyValue(summary, "canary.generate.summary.recipients", fmtInt(response.recipient_count));
  keyValue(
    summary,
    "canary.generate.summary.capacity",
    fmtInt(response.fingerprint_bits) + " " + t("compose.capacity.bits")
  );

  document.getElementById("canary-registry").value = response.registry;

  const host = document.getElementById("canary-versions");
  clear(host);
  response.versions.forEach((version) => {
    host.appendChild(renderCanaryVersion(version));
  });
}

function renderCanaryVersion(version) {
  const card = el("div", "signature");

  const head = el("div", "signature-head");
  const name = el("span", "signature-name");
  name.textContent = version.recipient_id;
  head.appendChild(name);
  const actions = el("div", "card-actions");
  const copy = el("button", "btn btn--small");
  copy.type = "button";
  setText(copy, "action.copy");
  copy.addEventListener("click", () => copyText(version.text));
  actions.appendChild(copy);
  head.appendChild(actions);
  card.appendChild(head);

  const fingerprint = el("div", "signature-detail is-mono");
  fingerprint.textContent = version.fingerprint_hex;
  card.appendChild(fingerprint);

  const output = el("textarea", "is-output");
  output.readOnly = true;
  output.rows = 2;
  output.value = version.text;
  card.appendChild(output);

  return card;
}

function clearCanaryGenerate() {
  ["canary-document", "canary-recipients", "canary-salt", "canary-registry"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  document.getElementById("canary-generate-result").hidden = true;
  clear(document.getElementById("canary-generate-message"));
  clear(document.getElementById("canary-versions"));
}

async function runCanaryTrace() {
  const message = document.getElementById("canary-trace-message");
  const leaked = await subjectOrFail("canary-leaked", "canary-leaked-file", message);
  if (leaked === null) return;
  const registry = document.getElementById("canary-trace-registry").value;
  if (!leaked.trim()) {
    showCalloutKey(message, "warning", "canary.trace.error.no_leaked");
    return;
  }
  if (!registry.trim()) {
    showCalloutKey(message, "warning", "canary.trace.error.no_registry");
    return;
  }
  const request = { leaked_text: leaked, registry };
  setStatus("status.working");
  try {
    const response = await invoke("canary_trace", { request });
    clear(message);
    renderCanaryTrace(response);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("canary-trace-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderCanaryTrace(response) {
  document.getElementById("canary-trace-result").hidden = false;

  const verdict = document.getElementById("canary-trace-verdict");
  clear(verdict);
  if (response.matched_recipient) {
    showCalloutKey(verdict, "success", "canary.trace.result.matched");
  } else if (response.confidence > 0) {
    showCalloutKey(verdict, "warning", "canary.trace.result.unmatched");
  } else {
    showCalloutKey(verdict, "info", "canary.trace.result.clean");
  }

  const summary = document.getElementById("canary-trace-summary");
  clear(summary);
  if (response.matched_recipient) {
    keyValue(summary, "canary.trace.result.recipient", response.matched_recipient);
  }
  keyValue(summary, "canary.trace.result.confidence", fmtPercent(response.confidence));
  if (response.extracted_fingerprint_hex) {
    keyValue(summary, "canary.trace.result.extracted", response.extracted_fingerprint_hex);
  }
}

function clearCanaryTrace() {
  ["canary-leaked", "canary-trace-registry"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  document.getElementById("canary-trace-result").hidden = true;
  clear(document.getElementById("canary-trace-message"));
}

/* ─── AI-regulation ────────────────────────────────────────── */

/* Variant per C2PA verdict, so the callout colour matches the reader's state.
   Absent is neutral, invalid is a failure, a valid-but-untrusted signature is a
   caution, a trusted one is a success. */
const C2PA_VERDICT_VARIANT = {
  absent: "info",
  invalid: "danger",
  signature_valid: "warning",
  trusted: "success",
};

/* Append backend summary or residual lines as muted notes. The lines are data
   the core returns, shown as they are, never a hardcoded string. */
function appendNotes(host, lines) {
  clear(host);
  (lines || []).forEach((line) => {
    const note = el("p", "field-hint");
    note.textContent = line;
    host.appendChild(note);
  });
}

/* A single muted note for an empty result section, from a catalogue key. */
function emptyNote(host, key) {
  clear(host);
  const note = el("p", "field-hint");
  setText(note, key);
  host.appendChild(note);
}

function airegChosenClasses() {
  return Array.from(document.querySelectorAll("#airegulation-clean-classes .aireg-class"))
    .filter((box) => box.checked)
    .map((box) => box.dataset.class);
}

/* Inspect */
async function runAiregInspect() {
  const message = document.getElementById("airegulation-inspect-message");
  const text = await subjectOrFail("airegulation-inspect-document", "airegulation-inspect-document-file", message);
  if (text === null) return;
  if (!text.trim()) {
    showCalloutKey(message, "warning", "airegulation.inspect.error.no_document");
    return;
  }
  setStatus("status.working");
  try {
    const report = await invoke("document_inspect", { request: { document: text } });
    clear(message);
    renderAiregInspect(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-inspect-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderAiregInspect(report) {
  document.getElementById("airegulation-inspect-result").hidden = false;

  const verdict = document.getElementById("airegulation-inspect-verdict");
  clear(verdict);
  const anyMarks =
    report.classes.some((finding) => finding.count > 0) || report.carrier_signatures.length > 0;
  if (anyMarks) {
    showCalloutKey(verdict, "warning", "airegulation.inspect.result.marks_found");
  } else {
    showCalloutKey(verdict, "success", "airegulation.inspect.result.clean");
  }

  const summary = document.getElementById("airegulation-inspect-summary");
  clear(summary);
  keyValue(summary, "airegulation.inspect.summary.total", fmtInt(report.total_chars));
  keyValue(summary, "airegulation.inspect.summary.visible", fmtInt(report.visible_chars));
  keyValue(summary, "airegulation.inspect.summary.invisible", fmtInt(report.invisible_chars));
  keyValue(summary, "airegulation.inspect.summary.verdict", report.verdict);
  keyValue(summary, "airegulation.inspect.summary.suspicion", fmtPercent(report.suspicion_score));

  const classes = document.getElementById("airegulation-inspect-classes");
  clear(classes);
  report.classes.forEach((finding) => {
    keyValue(classes, "airegulation.class." + finding.id, fmtInt(finding.count));
  });

  const other = document.getElementById("airegulation-inspect-other");
  clear(other);
  if (report.other_invisible.length) {
    report.other_invisible.forEach((entry) => {
      keyValue(other, entry.codepoint, entry.category + " " + fmtInt(entry.count));
    });
  } else {
    emptyNote(other, "airegulation.inspect.result.other_none");
  }

  appendNotes(document.getElementById("airegulation-inspect-notes"), report.summary);
}

function clearAiregInspect() {
  document.getElementById("airegulation-inspect-document").value = "";
  document.getElementById("airegulation-inspect-document-file").value = "";
  document.getElementById("airegulation-inspect-result").hidden = true;
  clear(document.getElementById("airegulation-inspect-message"));
}

/* Clean */
async function runAiregClean() {
  const message = document.getElementById("airegulation-clean-message");
  const text = await subjectOrFail("airegulation-clean-document", "airegulation-clean-document-file", message);
  if (text === null) return;
  if (!text.trim()) {
    showCalloutKey(message, "warning", "airegulation.clean.error.no_document");
    return;
  }
  const classes = airegChosenClasses();
  if (!classes.length) {
    showCalloutKey(message, "warning", "airegulation.clean.error.no_classes");
    return;
  }
  setStatus("status.working");
  try {
    const report = await invoke("document_clean", { request: { document: text, classes } });
    clear(message);
    renderAiregClean(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-clean-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderAiregClean(report) {
  document.getElementById("airegulation-clean-result").hidden = false;

  const altered = document.getElementById("airegulation-clean-altered");
  clear(altered);
  if (report.altered) {
    showCalloutKey(altered, "success", "airegulation.clean.result.altered");
  } else {
    showCalloutKey(altered, "info", "airegulation.clean.result.unaltered");
  }

  const removed = document.getElementById("airegulation-clean-removed");
  clear(removed);
  report.removed.forEach((entry) => {
    keyValue(removed, "airegulation.class." + entry.id, fmtInt(entry.count));
  });

  appendNotes(document.getElementById("airegulation-clean-residual"), report.residual);
  document.getElementById("airegulation-clean-output").value = report.cleaned_text;
}

function clearAiregClean() {
  document.getElementById("airegulation-clean-document").value = "";
  document.getElementById("airegulation-clean-document-file").value = "";
  document.getElementById("airegulation-clean-output").value = "";
  document.getElementById("airegulation-clean-result").hidden = true;
  clear(document.getElementById("airegulation-clean-message"));
  document
    .querySelectorAll("#airegulation-clean-classes .aireg-class")
    .forEach((box) => (box.checked = true));
}

/* Pristine clean */
async function runAiregPristine() {
  const message = document.getElementById("airegulation-pristine-message");
  const text = await subjectOrFail("airegulation-pristine-document", "airegulation-pristine-document-file", message);
  if (text === null) return;
  if (!text.trim()) {
    showCalloutKey(message, "warning", "airegulation.pristine.result.empty");
    return;
  }
  setStatus("status.working");
  try {
    const report = await invoke("document_pristine", { request: { document: text } });
    clear(message);
    renderAiregPristine(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-pristine-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderAiregPristine(report) {
  document.getElementById("airegulation-pristine-result").hidden = false;

  const altered = document.getElementById("airegulation-pristine-altered");
  clear(altered);
  if (report.altered) {
    showCalloutKey(altered, "success", "airegulation.pristine.result.altered");
  } else {
    showCalloutKey(altered, "info", "airegulation.pristine.result.unaltered");
  }

  const removed = document.getElementById("airegulation-pristine-removed");
  clear(removed);
  keyValue(removed, "airegulation.pristine.result.invisibles", fmtInt(report.invisibles_removed));
  report.class_removed.forEach((entry) => {
    keyValue(removed, "airegulation.class." + entry.id, fmtInt(entry.count));
  });

  appendNotes(document.getElementById("airegulation-pristine-notes"), report.notes);
  document.getElementById("airegulation-pristine-output").value = report.cleaned_text;
}

function clearAiregPristine() {
  document.getElementById("airegulation-pristine-document").value = "";
  document.getElementById("airegulation-pristine-document-file").value = "";
  document.getElementById("airegulation-pristine-output").value = "";
  document.getElementById("airegulation-pristine-result").hidden = true;
  clear(document.getElementById("airegulation-pristine-message"));
}

/* C2PA read */
async function airegC2paSource() {
  const fileInput = document.getElementById("airegulation-c2pa-file");
  if (fileInput.files && fileInput.files.length) {
    const buffer = await fileInput.files[0].arrayBuffer();
    return { bytes: Array.from(new Uint8Array(buffer)), name: fileInput.files[0].name };
  }
  const encoded = document.getElementById("airegulation-c2pa-base64").value.trim();
  if (encoded) {
    const binary = atob(encoded);
    const bytes = new Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return { bytes, name: null };
  }
  return null;
}

async function runAiregC2pa() {
  const message = document.getElementById("airegulation-c2pa-message");
  let source;
  try {
    source = await airegC2paSource();
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return;
  }
  if (!source || !source.bytes.length) {
    showCalloutKey(message, "warning", "airegulation.c2pa.error.no_input");
    return;
  }
  const hintField = document.getElementById("airegulation-c2pa-hint").value.trim();
  const format_hint = hintField || source.name || null;
  setStatus("status.working");
  try {
    const report = await invoke("c2pa_inspect", {
      request: { bytes: source.bytes, format_hint },
    });
    clear(message);
    renderAiregC2pa(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-c2pa-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderAiregC2pa(report) {
  document.getElementById("airegulation-c2pa-result").hidden = false;

  const verdict = document.getElementById("airegulation-c2pa-verdict");
  clear(verdict);
  const variant = C2PA_VERDICT_VARIANT[report.verdict] || "info";
  showCalloutKey(verdict, variant, "airegulation.c2pa.verdict." + report.verdict);

  const yesNo = (flag) => t(flag ? "airegulation.value.yes" : "airegulation.value.no");

  const summary = document.getElementById("airegulation-c2pa-summary");
  clear(summary);
  keyValue(summary, "airegulation.c2pa.summary.present", yesNo(report.present));
  keyValue(summary, "airegulation.c2pa.summary.verdict", t("airegulation.c2pa.verdict." + report.verdict));
  if (report.validation_state) {
    keyValue(summary, "airegulation.c2pa.summary.validation_state", report.validation_state);
  }
  keyValue(summary, "airegulation.c2pa.summary.trust", yesNo(report.trust_anchor_established));

  const failures = document.getElementById("airegulation-c2pa-failures");
  clear(failures);
  if (report.failures.length) {
    report.failures.forEach((failure) => {
      keyValue(failures, failure.code, failure.explanation || t("airegulation.value.none"));
    });
  } else {
    emptyNote(failures, "airegulation.c2pa.result.no_failures");
  }

  const manifest = document.getElementById("airegulation-c2pa-manifest");
  clear(manifest);
  const detail = report.manifest;
  if (detail) {
    if (detail.title) keyValue(manifest, "airegulation.c2pa.manifest.title", detail.title);
    if (detail.format) keyValue(manifest, "airegulation.c2pa.manifest.format", detail.format);
    if (detail.claim_generator) {
      keyValue(manifest, "airegulation.c2pa.manifest.generator", detail.claim_generator);
    }
    keyValue(manifest, "airegulation.c2pa.manifest.assertions", fmtInt(detail.assertion_labels.length));
    keyValue(manifest, "airegulation.c2pa.manifest.ingredients", fmtInt(detail.ingredient_count));
    if (detail.ai_generation) {
      keyValue(manifest, "airegulation.c2pa.manifest.ai", detail.ai_generation.note);
    }
    if (detail.signer) {
      if (detail.signer.issuer) keyValue(manifest, "airegulation.c2pa.manifest.issuer", detail.signer.issuer);
      if (detail.signer.common_name) {
        keyValue(manifest, "airegulation.c2pa.manifest.signer", detail.signer.common_name);
      }
      if (detail.signer.algorithm) {
        keyValue(manifest, "airegulation.c2pa.manifest.algorithm", detail.signer.algorithm);
      }
      if (detail.signer.signed_time) {
        keyValue(manifest, "airegulation.c2pa.manifest.signed_time", detail.signer.signed_time);
      }
    }
  } else {
    emptyNote(manifest, "airegulation.c2pa.result.no_manifest");
  }

  appendNotes(document.getElementById("airegulation-c2pa-notes"), report.summary);
}

function clearAiregC2pa() {
  document.getElementById("airegulation-c2pa-file").value = "";
  document.getElementById("airegulation-c2pa-base64").value = "";
  document.getElementById("airegulation-c2pa-hint").value = "";
  document.getElementById("airegulation-c2pa-result").hidden = true;
  clear(document.getElementById("airegulation-c2pa-message"));
}

/* Word-choice: analyze. Reads a text for marks carried in the choice of
   words and renders each finding with its localized certainty. The backend
   names the structural wall on every report; the empty note stands in when
   no finding rises above it. */
async function runAiregWmAnalyze() {
  const message = document.getElementById("airegulation-wm-analyze-message");
  const text = await subjectOrFail("airegulation-wm-analyze-text", "airegulation-wm-analyze-text-file", message);
  if (text === null) return;
  const acrostic = document.getElementById("airegulation-wm-analyze-acrostic").value.trim();
  const key = document.getElementById("airegulation-wm-analyze-key").value.trim();
  setStatus("status.working");
  try {
    const report = await invoke("wordmark_analyze", {
      request: { text, acrostic_target: acrostic, mark_key_hex: key },
    });
    clear(message);
    renderAiregWmAnalyze(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-wm-analyze-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderAiregWmAnalyze(report) {
  document.getElementById("airegulation-wm-analyze-result").hidden = false;
  const findings = document.getElementById("airegulation-wm-analyze-findings");
  clear(findings);
  const meaningful = report.findings.filter((finding) => finding.verdict !== "impossible");
  if (!meaningful.length) {
    emptyNote(findings, "airegulation.wordmark.analyze.result.empty");
  }
  report.findings.forEach((finding) => {
    keyValue(findings, "airegulation.wordmark.verdict." + finding.verdict, finding.detail);
  });
}

function clearAiregWmAnalyze() {
  document.getElementById("airegulation-wm-analyze-text").value = "";
  document.getElementById("airegulation-wm-analyze-text-file").value = "";
  document.getElementById("airegulation-wm-analyze-acrostic").value = "";
  document.getElementById("airegulation-wm-analyze-key").value = "";
  document.getElementById("airegulation-wm-analyze-result").hidden = true;
  clear(document.getElementById("airegulation-wm-analyze-message"));
}

/* The machine value of the chosen aggression, carried in data-value so the
   visible option label can stay in the locale catalogue. */
function airegScrubAggression() {
  const select = document.getElementById("airegulation-wm-scrub-aggression");
  const option = select.options[select.selectedIndex];
  return option ? option.dataset.value : "medium";
}

/* Word-choice: perturb. Best-effort local disruption of a synonym channel.
   It is a disruption, never a claimed removal; the note states that limit. */
async function runAiregWmScrub() {
  const message = document.getElementById("airegulation-wm-scrub-message");
  const text = await subjectOrFail("airegulation-wm-scrub-text", "airegulation-wm-scrub-text-file", message);
  if (text === null) return;
  const aggression = airegScrubAggression();
  setStatus("status.working");
  try {
    const report = await invoke("wordmark_scrub", { request: { text, aggression } });
    clear(message);
    renderAiregWmScrub(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-wm-scrub-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderAiregWmScrub(report) {
  document.getElementById("airegulation-wm-scrub-result").hidden = false;
  document.getElementById("airegulation-wm-scrub-changed").textContent = fmtInt(report.positions_changed);
  document.getElementById("airegulation-wm-scrub-total").textContent = fmtInt(report.synonym_positions);
  document.getElementById("airegulation-wm-scrub-output").value = report.text;
}

function clearAiregWmScrub() {
  document.getElementById("airegulation-wm-scrub-text").value = "";
  document.getElementById("airegulation-wm-scrub-text-file").value = "";
  document.getElementById("airegulation-wm-scrub-output").value = "";
  document.getElementById("airegulation-wm-scrub-result").hidden = true;
  clear(document.getElementById("airegulation-wm-scrub-message"));
  const select = document.getElementById("airegulation-wm-scrub-aggression");
  Array.from(select.options).forEach((option) => {
    option.selected = option.dataset.value === "medium";
  });
}

/* Append one muted note from a catalogue key without clearing its host, so the
   floor and re-clean notes can stack when both apply. The text is localized
   through setText, never a hardcoded string. */
function appendLocalizedNote(host, key) {
  const note = el("p", "field-hint");
  setText(note, key);
  host.appendChild(note);
}

/* Word-choice: rewrite. Sends the text to a model server the user chose to
   disrupt a word-choice mark. The send leaves the machine, so the backend gates
   it behind an acknowledgment: the first call without one is refused with the
   exact string "disclaimer_required", which reveals the disclaimer panel rather
   than an error. When the server is unreachable the backend falls back to a
   local perturbation and reports source "floor"; a re-clean of freshly added
   character marks is reported through reclean_applied. */
async function callRewrite(acknowledged) {
  const message = document.getElementById("airegulation-wm-rewrite-message");
  const text = await subjectOrFail("airegulation-wm-rewrite-text", "airegulation-wm-rewrite-text-file", message);
  if (text === null) return;
  const base_url = document.getElementById("airegulation-wm-rewrite-server").value.trim();
  const model = document.getElementById("airegulation-wm-rewrite-model").value.trim();
  setStatus("status.working");
  try {
    const report = await invoke("wordmark_rewrite", {
      request: { text, base_url, model, disclaimer_acknowledged: acknowledged },
    });
    clear(message);
    document.getElementById("airegulation-wm-rewrite-disclaimer").hidden = true;
    renderAiregWmRewrite(report);
    setStatus("status.done");
  } catch (error) {
    const detail = describeError(error);
    if (detail === "disclaimer_required") {
      clear(message);
      document.getElementById("airegulation-wm-rewrite-result").hidden = true;
      document.getElementById("airegulation-wm-rewrite-disclaimer").hidden = false;
      setStatus("status.ready");
      return;
    }
    document.getElementById("airegulation-wm-rewrite-result").hidden = true;
    showCallout(message, "danger", detail);
    setStatus("status.error");
  }
}

function runAiregWmRewrite() {
  callRewrite(false);
}

function renderAiregWmRewrite(report) {
  const notes = document.getElementById("airegulation-wm-rewrite-notes");
  clear(notes);
  if (report.source === "floor") {
    appendLocalizedNote(notes, "airegulation.wordmark.rewrite.result.floor_note");
  }
  if (report.reclean_applied) {
    appendLocalizedNote(notes, "airegulation.wordmark.rewrite.result.recleaned");
  }
  document.getElementById("airegulation-wm-rewrite-output").value = report.text;
  document.getElementById("airegulation-wm-rewrite-result").hidden = false;
}

/* The acknowledge control hides the disclaimer and retries the rewrite with the
   acknowledgment carried through, so the backend lets the send proceed. */
function acknowledgeAiregWmRewrite() {
  document.getElementById("airegulation-wm-rewrite-disclaimer").hidden = true;
  callRewrite(true);
}

function clearAiregWmRewrite() {
  document.getElementById("airegulation-wm-rewrite-text").value = "";
  document.getElementById("airegulation-wm-rewrite-text-file").value = "";
  document.getElementById("airegulation-wm-rewrite-output").value = "";
  document.getElementById("airegulation-wm-rewrite-disclaimer").hidden = true;
  document.getElementById("airegulation-wm-rewrite-result").hidden = true;
  clear(document.getElementById("airegulation-wm-rewrite-message"));
}

/* Word-choice: AI-origin estimate. Scores a text with two local models to
   estimate whether a model produced it. The models are embedded in the desktop
   build; a build without them reports the module unavailable, so the controls
   are hidden and the note revealed rather than left to fail on use. The score
   is a probable signal, never proof, as the result note states. */
async function initBinocularsAvailability() {
  const unavailable = document.getElementById("airegulation-wm-binoc-unavailable");
  const controls = document.getElementById("airegulation-wm-binoc-controls");
  try {
    const ok = await invoke("wordmark_binoculars_available");
    unavailable.hidden = ok;
    controls.hidden = !ok;
  } catch (error) {
    // A build that does not carry the command is treated as unavailable, so a
    // failure to probe never breaks startup.
    unavailable.hidden = false;
    controls.hidden = true;
  }
}

/* Load the two local models the score needs. The paths stay as the user set
   them; only the load status reflects progress, and a failure names itself. */
async function loadBinocModels() {
  const message = document.getElementById("airegulation-wm-binoc-message");
  const status = document.getElementById("airegulation-wm-binoc-loadstatus");
  const observer_path = document.getElementById("airegulation-wm-binoc-observer").value.trim();
  const performer_path = document.getElementById("airegulation-wm-binoc-performer").value.trim();
  setStatus("status.working");
  setText(status, "airegulation.wordmark.binoculars.load.loading");
  try {
    await invoke("wordmark_binoculars_load", {
      request: { observer_path, performer_path },
    });
    setText(status, "airegulation.wordmark.binoculars.load.loaded");
    setStatus("status.done");
  } catch (error) {
    clear(status);
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* Score the pasted text. On success the numeric score is shown and the result
   revealed; on error the result is hidden and the failure named. */
async function analyzeBinoculars() {
  const message = document.getElementById("airegulation-wm-binoc-message");
  const text = document.getElementById("airegulation-wm-binoc-text").value;
  setStatus("status.working");
  try {
    const report = await invoke("wordmark_binoculars_analyze", { request: { text } });
    clear(message);
    document.getElementById("airegulation-wm-binoc-score").textContent = report.score.toFixed(3);
    document.getElementById("airegulation-wm-binoc-result").hidden = false;
    setStatus("status.done");
  } catch (error) {
    document.getElementById("airegulation-wm-binoc-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function clearBinoculars() {
  document.getElementById("airegulation-wm-binoc-text").value = "";
  document.getElementById("airegulation-wm-binoc-score").textContent = "";
  document.getElementById("airegulation-wm-binoc-result").hidden = true;
  clear(document.getElementById("airegulation-wm-binoc-message"));
  clear(document.getElementById("airegulation-wm-binoc-loadstatus"));
}

/* ─── Files ────────────────────────────────────────────────── */

/* The cleaned document handed back by the last successful clean, held so the
   download control (separate from the clean run) can offer it to save. Reset
   whenever a new file is picked or the tab is cleared. */
let filesCleanDownload = null;

/* The stripped file handed back by the last successful metadata strip, held so
   its own download control can offer it to save. Reset like the clean hold. */
let filesStripDownload = null;

/* The pristine file handed back by the last successful pristine clean, held so
   its own download control can offer it to save. Reset like the clean hold. */
let filesPristineDownload = null;

/* The file extension, lower-cased, or an empty string when the name carries
   none. The backend maps this to a format and refuses an unknown one by name. */
function fileExtension(name) {
  const dot = name.lastIndexOf(".");
  return dot >= 0 && dot < name.length - 1 ? name.slice(dot + 1).toLowerCase() : "";
}

/* The base name without its extension, used to build the cleaned file's name. */
function fileBaseName(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

/* Read the picked document as a byte array, or null when nothing is chosen. The
   bytes are read locally and never leave the machine. */
async function filesPickedSource() {
  const input = document.getElementById("files-input");
  if (!input.files || !input.files.length) return null;
  const file = input.files[0];
  const buffer = await file.arrayBuffer();
  return {
    bytes: Array.from(new Uint8Array(buffer)),
    name: file.name,
    format: fileExtension(file.name),
  };
}

/* Hand a byte array back to the operator as a file to save, through an object
   URL and a programmatic download. No network origin is touched. */
function filesOfferDownload(bytes, filename) {
  const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const anchor = el("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

function filesRenderPicked(source) {
  const picked = document.getElementById("files-picked");
  clear(picked);
  if (!source) return;
  keyValue(picked, "files.picked.name", source.name);
  keyValue(picked, "files.picked.size", fmtInt(source.bytes.length));
}

/* A new file resets both results, so a stale inspect or clean is never left on
   screen beside a different document. */
async function onFilesPicked() {
  filesCleanDownload = null;
  filesStripDownload = null;
  filesPristineDownload = null;
  document.getElementById("files-inspect-result").hidden = true;
  document.getElementById("files-clean-result").hidden = true;
  document.getElementById("files-strip-result").hidden = true;
  document.getElementById("files-pristine-result").hidden = true;
  clear(document.getElementById("files-message"));
  clear(document.getElementById("files-clean-message"));
  clear(document.getElementById("files-strip-message"));
  clear(document.getElementById("files-pristine-message"));
  let source = null;
  try {
    source = await filesPickedSource();
  } catch (error) {
    showCallout(document.getElementById("files-message"), "danger", describeError(error));
  }
  filesRenderPicked(source);
}

/* Inspect */
async function runFilesInspect() {
  const message = document.getElementById("files-message");
  let source;
  try {
    source = await filesPickedSource();
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return;
  }
  if (!source || !source.bytes.length) {
    showCalloutKey(message, "warning", "files.error.no_file");
    return;
  }
  setStatus("status.working");
  try {
    const report = await invoke("file_inspect", {
      request: { bytes: source.bytes, format: source.format },
    });
    clear(message);
    renderFilesInspect(report);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("files-inspect-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderFilesInspect(report) {
  document.getElementById("files-inspect-result").hidden = false;

  const verdict = document.getElementById("files-inspect-verdict");
  clear(verdict);
  const anyMarks =
    report.classes.some((finding) => finding.count > 0) || report.carrier_signatures.length > 0;
  if (anyMarks) {
    showCalloutKey(verdict, "warning", "files.inspect.result.marks_found");
  } else {
    showCalloutKey(verdict, "success", "files.inspect.result.clean");
  }

  const summary = document.getElementById("files-inspect-summary");
  clear(summary);
  keyValue(summary, "files.inspect.summary.total", fmtInt(report.total_chars));
  keyValue(summary, "files.inspect.summary.visible", fmtInt(report.visible_chars));
  keyValue(summary, "files.inspect.summary.invisible", fmtInt(report.invisible_chars));
  keyValue(summary, "files.inspect.summary.verdict", report.verdict);
  keyValue(summary, "files.inspect.summary.suspicion", fmtPercent(report.suspicion_score));

  const classes = document.getElementById("files-inspect-classes");
  clear(classes);
  report.classes.forEach((finding) => {
    keyValue(classes, "files.class." + finding.id, fmtInt(finding.count));
  });

  const other = document.getElementById("files-inspect-other");
  clear(other);
  if (report.other_invisible.length) {
    report.other_invisible.forEach((entry) => {
      keyValue(other, entry.codepoint, entry.category + " " + fmtInt(entry.count));
    });
  } else {
    emptyNote(other, "files.inspect.result.other_none");
  }

  appendNotes(document.getElementById("files-inspect-notes"), report.summary);
}

function filesChosenClasses() {
  return Array.from(document.querySelectorAll("#files-clean-classes .files-class"))
    .filter((box) => box.checked)
    .map((box) => box.dataset.class);
}

/* Clean */
async function runFilesClean() {
  const message = document.getElementById("files-clean-message");
  let source;
  try {
    source = await filesPickedSource();
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return;
  }
  if (!source || !source.bytes.length) {
    showCalloutKey(message, "warning", "files.error.no_file");
    return;
  }
  const classes = filesChosenClasses();
  if (!classes.length) {
    showCalloutKey(message, "warning", "files.clean.error.no_classes");
    return;
  }
  setStatus("status.working");
  try {
    const response = await invoke("file_clean", {
      request: { bytes: source.bytes, format: source.format, classes },
    });
    clear(message);
    renderFilesClean(response, source);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("files-clean-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderFilesClean(response, source) {
  document.getElementById("files-clean-result").hidden = false;

  const altered = document.getElementById("files-clean-altered");
  clear(altered);
  if (response.altered) {
    showCalloutKey(altered, "success", "files.clean.result.altered");
  } else {
    showCalloutKey(altered, "info", "files.clean.result.unaltered");
  }

  const removed = document.getElementById("files-clean-removed");
  clear(removed);
  response.removed.forEach((entry) => {
    keyValue(removed, "files.class." + entry.id, fmtInt(entry.count));
  });

  appendNotes(document.getElementById("files-clean-residual"), response.residual);

  // Hold the cleaned bytes and a download name derived from the picked file.
  const downloadName = fileBaseName(source.name) + ".cleaned." + source.format;
  filesCleanDownload = { bytes: response.bytes, name: downloadName };

  // The cleaned text is a preview only for a text-native format. For a container
  // the response carries no text, so no preview is fabricated (invariant 2), and
  // the note explains the download is the useful result.
  const textField = document.getElementById("files-clean-text-field");
  const containerNote = document.getElementById("files-clean-container-note");
  if (response.cleaned_text !== null && response.cleaned_text !== undefined) {
    document.getElementById("files-clean-output").value = response.cleaned_text;
    textField.hidden = false;
    containerNote.hidden = true;
  } else {
    document.getElementById("files-clean-output").value = "";
    textField.hidden = true;
    containerNote.hidden = false;
  }
}

function runFilesDownload() {
  if (!filesCleanDownload) return;
  filesOfferDownload(filesCleanDownload.bytes, filesCleanDownload.name);
  setStatus("status.done");
}

/* Strip metadata */
async function runFilesStrip() {
  const message = document.getElementById("files-strip-message");
  let source;
  try {
    source = await filesPickedSource();
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return;
  }
  if (!source || !source.bytes.length) {
    showCalloutKey(message, "warning", "files.error.no_file");
    return;
  }
  setStatus("status.working");
  try {
    const response = await invoke("file_strip", {
      request: { bytes: source.bytes, format: source.format },
    });
    clear(message);
    renderFilesStrip(response, source);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("files-strip-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderFilesStrip(response, source) {
  document.getElementById("files-strip-result").hidden = false;

  const altered = document.getElementById("files-strip-altered");
  clear(altered);
  if (response.altered) {
    showCalloutKey(altered, "success", "files.strip.result.altered");
  } else {
    showCalloutKey(altered, "info", "files.strip.result.unaltered");
  }

  // Hold the stripped bytes and a download name derived from the picked file.
  const downloadName = fileBaseName(source.name) + ".stripped." + source.format;
  filesStripDownload = { bytes: response.bytes, name: downloadName };
}

function runFilesStripDownload() {
  if (!filesStripDownload) return;
  filesOfferDownload(filesStripDownload.bytes, filesStripDownload.name);
  setStatus("status.done");
}

/* Pristine clean */
async function runFilesPristine() {
  const message = document.getElementById("files-pristine-message");
  let source;
  try {
    source = await filesPickedSource();
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return;
  }
  if (!source || !source.bytes.length) {
    showCalloutKey(message, "warning", "files.error.no_file");
    return;
  }
  setStatus("status.working");
  try {
    const response = await invoke("file_pristine", {
      request: { bytes: source.bytes, format: source.format },
    });
    clear(message);
    renderFilesPristine(response, source);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("files-pristine-result").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderFilesPristine(response, source) {
  document.getElementById("files-pristine-result").hidden = false;

  const altered = document.getElementById("files-pristine-altered");
  clear(altered);
  if (response.altered) {
    showCalloutKey(altered, "success", "files.pristine.result.altered");
  } else {
    showCalloutKey(altered, "info", "files.pristine.result.unaltered");
  }

  const removed = document.getElementById("files-pristine-removed");
  clear(removed);
  keyValue(removed, "files.pristine.result.invisibles", fmtInt(response.invisibles_removed));
  response.class_removed.forEach((entry) => {
    keyValue(removed, "files.class." + entry.id, fmtInt(entry.count));
  });

  appendNotes(document.getElementById("files-pristine-notes"), response.notes);

  // Hold the cleaned bytes and a download name derived from the picked file.
  const downloadName = fileBaseName(source.name) + ".pristine." + source.format;
  filesPristineDownload = { bytes: response.bytes, name: downloadName };
}

function runFilesPristineDownload() {
  if (!filesPristineDownload) return;
  filesOfferDownload(filesPristineDownload.bytes, filesPristineDownload.name);
  setStatus("status.done");
}

function clearFiles() {
  filesCleanDownload = null;
  filesStripDownload = null;
  filesPristineDownload = null;
  document.getElementById("files-input").value = "";
  clear(document.getElementById("files-picked"));
  clear(document.getElementById("files-message"));
  clear(document.getElementById("files-clean-message"));
  clear(document.getElementById("files-strip-message"));
  clear(document.getElementById("files-pristine-message"));
  document.getElementById("files-inspect-result").hidden = true;
  document.getElementById("files-clean-result").hidden = true;
  document.getElementById("files-strip-result").hidden = true;
  document.getElementById("files-pristine-result").hidden = true;
  document.getElementById("files-clean-output").value = "";
  document
    .querySelectorAll("#files-clean-classes .files-class")
    .forEach((box) => (box.checked = true));
}

/* ─── Decoder (traced reveal) ──────────────────────────────── */

/* The generic role each wave category is labelled with. The concrete carrier
   or cipher is never named: the trace shows what the reader sees, a layer and
   its verdict, not how a layer is placed. */
const WAVE_ROLE_KEY = {
  identify: "decoder.wave.identify",
  carrier: "decoder.wave.carrier",
  envelope: "decoder.wave.envelope",
  confidentiality: "decoder.wave.confidentiality",
  integrity: "decoder.wave.integrity",
  recovery: "decoder.wave.recovery",
};

/* The oracle marker's shape, not its colour, carries the level, so the trace
   reads the same in greyscale. An exact verdict is solid, a probabilistic score
   is striped, an undetermined or purely structural step is hollow, and the wave
   that halted the chain is the failed anchor. */
const SHAPE_CLASS = {
  solid: "wave-oracle--solid",
  striped: "wave-oracle--striped",
  hollow: "wave-oracle--hollow",
  failed: "wave-oracle--failed",
};

/* The legend printed under the trace, so the shape language is explained where
   it is used. */
const ORACLE_LEGEND = [
  { shape: "solid", tag: "decoder.oracle.tag_exact", desc: "decoder.oracle.legend_exact" },
  { shape: "striped", tag: "decoder.oracle.tag_probabilistic", desc: "decoder.oracle.legend_probabilistic" },
  { shape: "hollow", tag: "decoder.oracle.tag_undetermined", desc: "decoder.oracle.legend_undetermined" },
];

/* The shape a wave is drawn with, from its verdict and the oracle that judged
   it. A probabilistic score is never given a solid, exact shape. */
function waveShape(wave) {
  if (wave.verdict === "failed") return "failed";
  if (wave.verdict === "undetermined") return "hollow";
  if (wave.oracle === "aead_tag" || wave.oracle === "checksum") return "solid";
  if (wave.oracle === "ngram") return "striped";
  return "hollow";
}

/* The word shown inside the oracle marker: honest about what verified the wave,
   or that nothing did. */
function waveOracleKey(wave) {
  if (wave.verdict === "failed") return "decoder.oracle.failed";
  if (wave.verdict === "undetermined") return "decoder.oracle.undetermined";
  switch (wave.oracle) {
    case "aead_tag": return "decoder.oracle.authenticated";
    case "checksum": return "decoder.oracle.integrity";
    case "ngram": return "decoder.oracle.language";
    default: return "decoder.oracle.structural";
  }
}

function renderWave(wave) {
  const row = el("div", "wave");
  const shape = waveShape(wave);
  if (shape === "failed") row.classList.add("wave--failed");

  const mark = el("span", "wave-oracle " + SHAPE_CLASS[shape]);
  setText(mark, waveOracleKey(wave));

  const body = el("div", "wave-body");
  const role = el("div", "wave-role");
  setText(role, WAVE_ROLE_KEY[wave.category] || "decoder.wave.carrier");
  body.appendChild(role);
  if (wave.reason) {
    const detail = el("div", "wave-detail");
    detail.textContent = wave.reason;
    body.appendChild(detail);
  }

  const meta = el("div", "wave-meta");
  [
    t("decoder.wave.input") + " " + fmtInt(wave.input_bytes) + " " + t("decoder.wave.bytes"),
    t("decoder.wave.output") + " " + fmtInt(wave.output_bytes) + " " + t("decoder.wave.bytes"),
    t("decoder.wave.elapsed") + " " + fmtInt(wave.elapsed_micros) + " " + t("decoder.wave.micros"),
  ].forEach((line) => {
    const span = el("div");
    span.textContent = line;
    meta.appendChild(span);
  });

  row.appendChild(mark);
  row.appendChild(body);
  row.appendChild(meta);
  return row;
}

function renderDecoderLegend() {
  const host = document.getElementById("decoder-oracle-legend");
  clear(host);
  ORACLE_LEGEND.forEach((entry) => {
    const row = el("div", "wave-legend-row");
    const mark = el("span", "wave-oracle " + SHAPE_CLASS[entry.shape]);
    setText(mark, entry.tag);
    const label = el("span", "field-hint");
    setText(label, entry.desc);
    row.appendChild(mark);
    row.appendChild(label);
    host.appendChild(row);
  });
}

/* The single headline verdict, kept honest: a recovered and exactly verified
   payload reads as verified; a recovered but unverified one says so; a run that
   found no header offers recovery; a halt names itself; nothing found is
   undetermined, never a failure. */
function decoderOutcome(response) {
  if (response.recovered) {
    return response.integrity
      ? { key: "decoder.outcome.verified", cls: "badge--success" }
      : { key: "decoder.outcome.recovered_unverified", cls: "badge--warning" };
  }
  if (response.recovery_available) {
    return { key: "decoder.outcome.no_header", cls: "badge--info" };
  }
  if (response.waves.some((wave) => wave.verdict === "failed")) {
    return { key: "decoder.outcome.halted", cls: "badge--danger" };
  }
  return { key: "decoder.outcome.undetermined", cls: "badge--info" };
}

async function runDecoder() {
  const message = document.getElementById("decoder-message");
  clear(document.getElementById("decoder-recovery-prompt"));
  // A picked document resolves to its text first, so the traced decoder reads a
  // marked file exactly as it reads pasted text.
  let text;
  try {
    text = await resolveTextOrFile("decoder-text", "decoder-file");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    return;
  }
  if (!text.trim()) {
    showCalloutKey(message, "warning", "decoder.error.no_text");
    return;
  }
  const password = document.getElementById("decoder-password").value;
  const recovery = document.getElementById("decoder-recovery").checked;
  setStatus("status.working");
  try {
    const response = await invoke("reveal_traced", {
      text,
      password: password || null,
      recovery,
    });
    clear(message);
    renderDecoder(response);
    setStatus("status.done");
  } catch (error) {
    document.getElementById("decoder-payload-card").hidden = true;
    document.getElementById("decoder-trace-card").hidden = true;
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

function renderDecoder(response) {
  // Recovery is a declared mode: when a standard pass found no header, the
  // control is offered, never turned on silently.
  const prompt = document.getElementById("decoder-recovery-prompt");
  clear(prompt);
  if (response.recovery_available) {
    showCalloutKey(prompt, "info", "decoder.recovery.prompt");
  }

  const payloadCard = document.getElementById("decoder-payload-card");
  if (response.recovered) {
    payloadCard.hidden = false;

    const outcome = decoderOutcome(response);
    const badge = document.getElementById("decoder-outcome-badge");
    badge.className = "badge " + outcome.cls;
    setText(badge, outcome.key);

    const note = document.getElementById("decoder-payload-note");
    clear(note);
    const output = document.getElementById("decoder-output");
    if (response.hidden_text !== null && response.hidden_text !== undefined) {
      output.value = response.hidden_text;
      output.hidden = false;
    } else {
      output.value = "";
      output.hidden = true;
      const binary = el("div", "callout callout--info");
      binary.textContent = t("decoder.payload.binary") + " " +
        fmtInt(response.hidden_size_bytes || 0) + " " + t("decoder.wave.bytes");
      note.appendChild(binary);
    }

    const summary = document.getElementById("decoder-summary");
    clear(summary);
    keyValue(
      summary,
      "decoder.summary.carriers",
      response.carriers_detected.length
        ? response.carriers_detected.map((id) => t("carrier." + id + ".name")).join(", ")
        : t("decoder.summary.none")
    );
    keyValue(
      summary,
      "decoder.summary.size",
      fmtInt(response.hidden_size_bytes || 0) + " " + t("decoder.wave.bytes")
    );
    keyValue(
      summary,
      "decoder.summary.recovery",
      t(response.recovery_used ? "decoder.summary.recovery_used" : "decoder.summary.recovery_standard")
    );

    const warnings = document.getElementById("decoder-warnings");
    clear(warnings);
    showCalloutKey(
      warnings,
      response.integrity ? "success" : "warning",
      response.integrity ? "decoder.integrity.verified" : "decoder.integrity.unverified"
    );
    (response.warnings || []).forEach((line) => {
      const box = el("div", "callout");
      box.textContent = line;
      warnings.appendChild(box);
    });
  } else {
    payloadCard.hidden = true;
  }

  // The wave trace is the artefact: it renders whether the reveal succeeded or
  // not, so a failure is shown as a location rather than a bare error.
  document.getElementById("decoder-trace-card").hidden = false;
  const host = document.getElementById("decoder-waves");
  clear(host);
  (response.waves || []).forEach((wave) => host.appendChild(renderWave(wave)));

  if (!response.recovered && !response.recovery_available) {
    const banner = el("div", "callout callout--" + (response.error ? "danger" : "info"));
    banner.textContent = response.error
      ? describeError(response.error)
      : t("decoder.trace.undetermined");
    host.appendChild(banner);
  }

  renderDecoderLegend();
  document.getElementById("decoder-json").textContent = JSON.stringify(response, null, 2);
}

function clearDecoder() {
  ["decoder-text", "decoder-password", "decoder-output", "decoder-file"].forEach((id) => {
    document.getElementById(id).value = "";
  });
  document.getElementById("decoder-recovery").checked = false;
  document.getElementById("decoder-payload-card").hidden = true;
  document.getElementById("decoder-trace-card").hidden = true;
  clear(document.getElementById("decoder-message"));
  clear(document.getElementById("decoder-recovery-prompt"));
  clear(document.getElementById("decoder-warnings"));
}

/* ─── Settings ─────────────────────────────────────────────── */

/* The confidentiality-layer options for the default-layer select. Rebuilt on a
   locale change so the names follow the language. The "none" option is offered
   exactly as the engine allows a default of no confidentiality layer. */
function renderSettingsCipherOptions() {
  const select = document.getElementById("settings-cipher");
  if (!select) return;
  const previous = select.value;
  clear(select);

  const none = el("option");
  none.value = SETTINGS_CIPHER_NONE;
  setText(none, "cipher.none.name");
  select.appendChild(none);

  state.ciphers.forEach((id) => {
    const option = el("option");
    option.value = id;
    setText(option, "cipher." + id + ".name");
    select.appendChild(option);
  });

  const stored = state.settings ? state.settings.crypto.default_cipher : SETTINGS_CIPHER_NONE;
  select.value = previous || stored || SETTINGS_CIPHER_NONE;
  if (!select.value) select.value = SETTINGS_CIPHER_NONE;
}

/* Reflect the accepted ranges the core returns onto the number inputs, so the
   interface's bounds come from the engine and cannot drift from it. */
function applySettingsConstraints() {
  const constraints = state.settingsConstraints;
  if (!constraints) return;
  const bound = (id, spec) => {
    const input = document.getElementById(id);
    if (!input || !spec) return;
    if (spec.minimum !== undefined) input.min = spec.minimum;
    if (spec.maximum !== undefined) input.max = spec.maximum;
  };
  if (constraints.density) {
    bound("settings-density-conceal", constraints.density.conceal);
    bound("settings-density-sign", constraints.density.sign);
    bound("settings-density-mark", constraints.density.mark);
  }
  if (constraints.crypto) {
    bound("settings-crypto-memory", constraints.crypto.memory_kib);
    bound("settings-crypto-passes", constraints.crypto.time_cost);
    bound("settings-crypto-parallelism", constraints.crypto.parallelism);
  }
}

/* Paint the number inputs and the default-layer select from the settings in
   force. Called on load, reload and after an accepted change, never on a locale
   change (which must not discard an edit that has not been applied yet). */
function paintSettingsInputs() {
  const settings = state.settings;
  if (!settings) return;
  document.getElementById("settings-density-conceal").value = settings.density.conceal;
  document.getElementById("settings-density-sign").value = settings.density.sign;
  document.getElementById("settings-density-mark").value = settings.density.mark;
  document.getElementById("settings-crypto-memory").value = settings.crypto.memory_kib;
  document.getElementById("settings-crypto-passes").value = settings.crypto.time_cost;
  document.getElementById("settings-crypto-parallelism").value = settings.crypto.parallelism;
  const select = document.getElementById("settings-cipher");
  select.value = settings.crypto.default_cipher || SETTINGS_CIPHER_NONE;
  if (!select.value) select.value = SETTINGS_CIPHER_NONE;
}

/* The read-back: the values the core reports it is holding after the last
   change. This is what the interface shows as "in effect now", so a report
   never claims a value the engine did not store. */
function paintSettingsReadback() {
  const host = document.getElementById("settings-readback");
  if (!host) return;
  clear(host);
  const settings = state.settings;
  if (!settings) return;
  keyValue(host, "settings.readback.conceal", fmtFixed(settings.density.conceal, 2));
  keyValue(host, "settings.readback.sign", fmtFixed(settings.density.sign, 2));
  keyValue(host, "settings.readback.mark", fmtFixed(settings.density.mark, 2));
  keyValue(host, "settings.readback.memory", fmtInt(settings.crypto.memory_kib));
  keyValue(host, "settings.readback.passes", fmtInt(settings.crypto.time_cost));
  keyValue(host, "settings.readback.parallelism", fmtInt(settings.crypto.parallelism));
  const cipher = settings.crypto.default_cipher;
  const cipherName = cipher === SETTINGS_CIPHER_NONE
    ? t("cipher.none.name")
    : t("cipher." + cipher + ".name");
  keyValue(host, "settings.readback.cipher", cipherName);
  document.getElementById("settings-json").textContent = JSON.stringify(settings, null, 2);
}

/* Take in a settings_read or settings_update result: the settings object always
   comes back; the constraints come with a read and are kept across an update. */
function absorbSettings(view) {
  if (view && view.settings) state.settings = view.settings;
  if (view && view.constraints) state.settingsConstraints = view.constraints;
  applySettingsConstraints();
  paintSettingsInputs();
  renderSettingsCipherOptions();
  paintSettingsReadback();
  document.getElementById("settings-result").hidden = false;
}

async function loadSettings() {
  const view = await invoke("settings_read");
  absorbSettings(view);
}

/* Collect the edited fields into a partial update. A field left blank is
   omitted, so it stays at its stored value; a finite out-of-range value is sent
   as typed, so the core refuses it by name rather than the interface hiding it. */
function collectSettingsUpdate() {
  const readNumber = (id) => {
    const input = document.getElementById(id);
    if (!input) return null;
    const raw = input.value;
    if (raw === "" || raw === null) return null;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : null;
  };

  const density = {};
  const conceal = readNumber("settings-density-conceal");
  const sign = readNumber("settings-density-sign");
  const mark = readNumber("settings-density-mark");
  if (conceal !== null) density.conceal = conceal;
  if (sign !== null) density.sign = sign;
  if (mark !== null) density.mark = mark;

  const crypto = {};
  const memory = readNumber("settings-crypto-memory");
  const passes = readNumber("settings-crypto-passes");
  const parallelism = readNumber("settings-crypto-parallelism");
  if (memory !== null) crypto.memory_kib = memory;
  if (passes !== null) crypto.time_cost = passes;
  if (parallelism !== null) crypto.parallelism = parallelism;
  crypto.default_cipher = document.getElementById("settings-cipher").value || SETTINGS_CIPHER_NONE;

  const update = { crypto };
  if (Object.keys(density).length) update.density = density;
  return update;
}

async function runSettingsApply() {
  const message = document.getElementById("settings-message");
  setStatus("status.working");
  try {
    const update = collectSettingsUpdate();
    const view = await invoke("settings_update", { update });
    absorbSettings(view);
    showCalloutKey(message, "success", "settings.result.applied");
    setStatus("status.done");
  } catch (error) {
    // The core refused the write and changed nothing. Show its named refusal
    // exactly, so the reader learns which field was refused and why.
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

async function runSettingsReload() {
  const message = document.getElementById("settings-message");
  setStatus("status.working");
  try {
    await loadSettings();
    clear(message);
    setStatus("status.done");
  } catch (error) {
    showCallout(message, "danger", describeError(error));
    setStatus("status.error");
  }
}

/* ─── About ────────────────────────────────────────────────── */

function renderBuildInfo() {
  const host = document.getElementById("about-build");
  clear(host);
  if (state.appInfo) {
    keyValue(host, "about.build.version", state.appInfo.version);
    keyValue(host, "about.build.identifier", state.appInfo.identifier);
  }
  keyValue(host, "about.build.locale_directory", state.localeDirectory);
  keyValue(host, "about.build.locale_active", state.locale);
  keyValue(
    host,
    "about.build.locale_found",
    state.locales.map((entry) => entry.code).join(", ")
  );
  document.getElementById("status-version").textContent = state.appInfo
    ? state.appInfo.version
    : "";
}

/* ─── Wiring ───────────────────────────────────────────────── */

function bindEvents() {
  document.getElementById("compose-run").addEventListener("click", runCompose);
  document.getElementById("compose-measure").addEventListener("click", runMeasure);
  document.getElementById("compose-clear").addEventListener("click", clearCompose);
  document.getElementById("compose-copy").addEventListener("click", () => copyFrom("compose-output"));
  document.getElementById("compose-cover").addEventListener("input", () => {
    refreshCapacity();
    refreshMission();
    hideRecommendation();
  });
  document.getElementById("compose-secret").addEventListener("input", () => {
    state.requiredBits = null;
    paintCapacity();
    refreshMission();
    hideRecommendation();
  });
  document
    .getElementById("compose-recommend")
    .addEventListener("click", requestRecommendation);
  document
    .getElementById("compose-recommendation-apply")
    .addEventListener("click", applyRecommendation);
  document
    .getElementById("compose-recommendation-ignore")
    .addEventListener("click", hideRecommendation);
  document.getElementById("compose-cipher").addEventListener("change", () => {
    state.requiredBits = null;
    paintCipherNote();
    paintCapacity();
    refreshMission();
  });
  document.getElementById("compose-password").addEventListener("input", refreshMission);
  document.getElementById("compose-density").addEventListener("input", onDensityInput);
  document.getElementById("compose-robust").addEventListener("change", (event) => {
    state.robust = event.target.checked;
    refreshCapacity();
    refreshMission();
    hideRecommendation();
  });
  document.getElementById("compose-saturate").addEventListener("change", (event) => {
    state.saturate = event.target.checked;
    hideRecommendation();
  });
  document.getElementById("compose-payload-attach").addEventListener("click", runComposeAttach);

  composeCoverImport = wireFileImport({
    textareaId: "compose-cover",
    fileInputId: "compose-cover-file",
    frameId: "compose-cover-frame",
    overlayId: "compose-cover-overlay",
    nameId: "compose-cover-name",
    extId: "compose-cover-ext",
    removeId: "compose-cover-remove",
    // A new cover file, or dropping back to text, invalidates a shown result and
    // the marked file it offered, so a stale result is never left beside a
    // changed input. The engine measures the real capacity gate at conceal time.
    onChange: () => {
      composeFileDownload = null;
      document.getElementById("compose-download").hidden = true;
      document.getElementById("compose-result").hidden = true;
      setProgress("compose-progress", false);
      clear(document.getElementById("compose-message"));
    },
    onError: (error) => {
      showCallout(document.getElementById("compose-message"), "danger", describeError(error));
    },
  });
  document.getElementById("compose-download").addEventListener("click", runComposeDownload);
  document.getElementById("compose-export").addEventListener("click", () =>
    runExport("compose-output", "steganohero-marked", "compose-export-format", "compose-message")
  );

  decodeFileImport = wireFileImport({
    textareaId: "decode-text",
    fileInputId: "decode-file",
    frameId: "decode-input-frame",
    overlayId: "decode-file-overlay",
    nameId: "decode-file-name",
    extId: "decode-file-ext",
    removeId: "decode-file-remove",
    // A new marked file, or dropping back to text, invalidates a shown result and
    // the recovered file it offered, so a stale result is never left beside a
    // changed input.
    onChange: () => {
      decodeFileDownload = null;
      document.getElementById("decode-download").hidden = true;
      document.getElementById("decode-result").hidden = true;
      setProgress("decode-progress", false);
      clear(document.getElementById("decode-message"));
    },
    onError: (error) => {
      showCallout(document.getElementById("decode-message"), "danger", describeError(error));
    },
  });
  document.getElementById("decode-run").addEventListener("click", runDecode);
  document.getElementById("decode-clear").addEventListener("click", clearDecode);
  document.getElementById("decode-keypair-generate").addEventListener("click", runPqcKeypair);
  document.getElementById("decode-copy").addEventListener("click", () => copyFrom("decode-output"));
  document.getElementById("decode-download").addEventListener("click", runDecodeDownload);
  document.getElementById("decode-export").addEventListener("click", () =>
    runExport("decode-output", "steganohero-revealed", "decode-export-format", "decode-message")
  );
  document.getElementById("airegulation-clean-export").addEventListener("click", () =>
    runExport("airegulation-clean-output", "cleaned", "airegulation-clean-export-format", "airegulation-clean-message")
  );
  document.getElementById("airegulation-pristine-export").addEventListener("click", () =>
    runExport("airegulation-pristine-output", "pristine", "airegulation-pristine-export-format", "airegulation-pristine-message")
  );
  document.getElementById("airegulation-wm-scrub-export").addEventListener("click", () =>
    runExport("airegulation-wm-scrub-output", "scrubbed", "airegulation-wm-scrub-export-format", "airegulation-wm-scrub-message")
  );
  document.getElementById("airegulation-wm-rewrite-export").addEventListener("click", () =>
    runExport("airegulation-wm-rewrite-output", "rewritten", "airegulation-wm-rewrite-export-format", "airegulation-wm-rewrite-message")
  );
  document.getElementById("decode-recover-run").addEventListener("click", runRecoverAttachments);
  document.getElementById("decode-recover-clear").addEventListener("click", clearRecoverAttachments);

  analyzeFileImport = wireFileImport({
    textareaId: "analyze-text",
    fileInputId: "analyze-file",
    frameId: "analyze-input-frame",
    overlayId: "analyze-file-overlay",
    nameId: "analyze-file-name",
    extId: "analyze-file-ext",
    removeId: "analyze-file-remove",
    // A new file, or dropping back to text, invalidates the shown report and
    // its export, so a stale report is never exported beside a changed input.
    onChange: () => {
      analyzeLastReport = null;
      document.getElementById("analyze-export").hidden = true;
    },
    onError: (error) => {
      showCallout(document.getElementById("analyze-message"), "danger", describeError(error));
    },
  });
  document.getElementById("analyze-run").addEventListener("click", runAnalyze);
  document.getElementById("analyze-clear").addEventListener("click", clearAnalyze);
  document.getElementById("analyze-export").addEventListener("click", runAnalyzeExport);
  document.getElementById("compare-run").addEventListener("click", runCompare);

  document.getElementById("identity-generate").addEventListener("click", runGenerateIdentity);
  document.getElementById("identity-copy-public").addEventListener("click", () => copyFrom("identity-public"));
  document.getElementById("identity-copy-private").addEventListener("click", () => copyFrom("identity-private"));
  document.getElementById("mark-run").addEventListener("click", runMark);
  document.getElementById("mark-clear").addEventListener("click", clearMark);
  document.getElementById("mark-copy-sidecar").addEventListener("click", () => copyFrom("mark-sidecar"));
  document.getElementById("mark-copy-marked").addEventListener("click", () => copyFrom("mark-marked"));
  document.getElementById("mark-marked-export").addEventListener("click", () =>
    runExport("mark-marked", "steganohero-marked", "mark-marked-export-format", "mark-message")
  );
  document.getElementById("mark-binding").addEventListener("change", paintBindingNote);
  ["assert-human", "assert-ai", "assert-recipient"].forEach((id) => {
    document.getElementById(id).addEventListener("change", syncAssertionFields);
  });
  document.getElementById("verify-run").addEventListener("click", runVerify);
  document.getElementById("verify-clear").addEventListener("click", clearVerify);

  document.getElementById("canary-generate-run").addEventListener("click", runCanaryGenerate);
  document.getElementById("canary-generate-clear").addEventListener("click", clearCanaryGenerate);
  document.getElementById("canary-copy-registry").addEventListener("click", () => copyFrom("canary-registry"));
  document.getElementById("canary-trace-run").addEventListener("click", runCanaryTrace);
  document.getElementById("canary-trace-clear").addEventListener("click", clearCanaryTrace);

  document.getElementById("airegulation-inspect-run").addEventListener("click", runAiregInspect);
  document.getElementById("airegulation-inspect-clear").addEventListener("click", clearAiregInspect);
  document.getElementById("airegulation-clean-run").addEventListener("click", runAiregClean);
  document.getElementById("airegulation-clean-clear").addEventListener("click", clearAiregClean);
  document.getElementById("airegulation-clean-copy").addEventListener("click", () => copyFrom("airegulation-clean-output"));
  document.getElementById("airegulation-pristine-run").addEventListener("click", runAiregPristine);
  document.getElementById("airegulation-pristine-clear").addEventListener("click", clearAiregPristine);
  document.getElementById("airegulation-pristine-copy").addEventListener("click", () => copyFrom("airegulation-pristine-output"));
  document.getElementById("airegulation-c2pa-run").addEventListener("click", runAiregC2pa);
  document.getElementById("airegulation-c2pa-clear").addEventListener("click", clearAiregC2pa);

  document.getElementById("airegulation-wm-analyze-run").addEventListener("click", runAiregWmAnalyze);
  document.getElementById("airegulation-wm-analyze-clear").addEventListener("click", clearAiregWmAnalyze);
  document.getElementById("airegulation-wm-scrub-run").addEventListener("click", runAiregWmScrub);
  document.getElementById("airegulation-wm-scrub-clear").addEventListener("click", clearAiregWmScrub);
  document.getElementById("airegulation-wm-scrub-copy").addEventListener("click", () => copyFrom("airegulation-wm-scrub-output"));
  document.getElementById("airegulation-wm-rewrite-run").addEventListener("click", runAiregWmRewrite);
  document.getElementById("airegulation-wm-rewrite-clear").addEventListener("click", clearAiregWmRewrite);
  document.getElementById("airegulation-wm-rewrite-ack").addEventListener("click", acknowledgeAiregWmRewrite);
  document.getElementById("airegulation-wm-rewrite-copy").addEventListener("click", () => copyFrom("airegulation-wm-rewrite-output"));
  document.getElementById("airegulation-wm-binoc-load").addEventListener("click", loadBinocModels);
  document.getElementById("airegulation-wm-binoc-analyze").addEventListener("click", analyzeBinoculars);
  document.getElementById("airegulation-wm-binoc-clear").addEventListener("click", clearBinoculars);

  document.getElementById("files-input").addEventListener("change", onFilesPicked);
  document.getElementById("files-inspect-run").addEventListener("click", runFilesInspect);
  document.getElementById("files-clear").addEventListener("click", clearFiles);
  document.getElementById("files-clean-run").addEventListener("click", runFilesClean);
  document.getElementById("files-clean-download").addEventListener("click", runFilesDownload);
  document.getElementById("files-clean-copy").addEventListener("click", () => copyFrom("files-clean-output"));
  document.getElementById("files-strip-run").addEventListener("click", runFilesStrip);
  document.getElementById("files-strip-download").addEventListener("click", runFilesStripDownload);
  document.getElementById("files-pristine-run").addEventListener("click", runFilesPristine);
  document.getElementById("files-pristine-download").addEventListener("click", runFilesPristineDownload);

  document.getElementById("decoder-run").addEventListener("click", runDecoder);
  document.getElementById("decoder-clear").addEventListener("click", clearDecoder);
  document.getElementById("decoder-copy").addEventListener("click", () => copyFrom("decoder-output"));
  document.getElementById("decoder-export").addEventListener("click", () =>
    runExport("decoder-output", "steganohero-revealed", "decoder-export-format", "decoder-message")
  );
  document.getElementById("restmcp-configure").addEventListener("click", runRestMcpConfigure);
  document.getElementById("restmcp-copy-snippet").addEventListener("click", () => copyFrom("restmcp-snippet"));

  document.getElementById("settings-apply").addEventListener("click", runSettingsApply);
  document.getElementById("settings-reload").addEventListener("click", runSettingsReload);
}

function reportFatal(error) {
  const failure = document.getElementById("bootstrap-failure");
  document.getElementById("bootstrap-failure-detail").textContent = describeError(error);
  document.getElementById("shell").hidden = true;
  failure.hidden = false;
}

async function bootstrap() {
  applyTheme(currentThemeMode());

  const environment = await invoke("locale_environment");
  state.locales = environment.available;
  state.baseLocale = environment.base_locale;
  state.environmentHint = environment.environment_hint;
  state.localeDirectory = environment.directory;

  state.carriers = await invoke("list_carriers");
  state.ciphers = await invoke("list_ciphers");
  state.exportFormats = await invoke("export_formats");
  state.appInfo = await invoke("app_info");

  // Carrier flags are needed before the chips are drawn, so that a carrier the
  // engine cannot read back is labelled from the very first paint.
  state.capacities = await invoke("carrier_capacity", { cover: "", robust: state.robust });

  // The runtime engine configuration, read from the shared core config path.
  await loadSettings();

  const code = resolveLocale(state.locales, state.environmentHint, state.baseLocale);
  await setLocale(code, false);

  renderExportSelects();
  bindEvents();
  // Availability of the AI-origin estimate depends on whether this desktop
  // build carries the embedded model; the probe is self-guarded, so a failure
  // to invoke leaves startup intact and the module reads as unavailable.
  await initBinocularsAvailability();
  selectTab(TAB_IDS[0]);
  refreshCapacity();
  refreshMission();
  checkComposition();
  document.getElementById("shell").hidden = false;
}

bootstrap().catch(reportFatal);
