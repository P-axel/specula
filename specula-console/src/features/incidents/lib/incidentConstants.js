export const KIND_LABELS = {
  network: "Réseau",
  system: "Système",
  identity: "Identité",
  application: "Application",
  correlated: "Corrélé",
  vulnerability: "Vulnérabilité",
  generic: "Autre",
};

export const DEFAULT_INCIDENT_FILTERS = {
  search: "",
  kind: "all",
  severity: "all",
  status: "active",   // "active" = open + investigating par défaut
  age: "all",
};

export const ACTIVE_STATUSES = ["open", "investigating"];