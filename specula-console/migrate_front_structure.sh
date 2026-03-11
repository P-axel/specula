#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="src"
TS="$(date +%Y%m%d-%H%M%S)"

echo "==> Migration douce de l'arborescence React"
echo "==> Dossier courant: $(pwd)"

if [ ! -d "$SRC_DIR" ]; then
  echo "Erreur: dossier 'src' introuvable. Lance ce script depuis la racine de specula-console."
  exit 1
fi

mkdir -p \
  "$SRC_DIR/app" \
  "$SRC_DIR/core/api" \
  "$SRC_DIR/core/layout" \
  "$SRC_DIR/shared/components" \
  "$SRC_DIR/shared/utils" \
  "$SRC_DIR/features/assets/api" \
  "$SRC_DIR/features/assets/components" \
  "$SRC_DIR/features/assets/pages" \
  "$SRC_DIR/features/alerts/api" \
  "$SRC_DIR/features/alerts/components" \
  "$SRC_DIR/features/alerts/pages" \
  "$SRC_DIR/features/detections/api" \
  "$SRC_DIR/features/detections/components" \
  "$SRC_DIR/features/detections/pages" \
  "$SRC_DIR/modules"

safe_move() {
  local src="$1"
  local dst="$2"

  if [ ! -e "$src" ]; then
    echo "SKIP  : $src absent"
    return 0
  fi

  mkdir -p "$(dirname "$dst")"

  if [ -e "$dst" ]; then
    local backup="${dst}.bak.${TS}"
    echo "BACKUP: $dst -> $backup"
    mv "$dst" "$backup"
  fi

  echo "MOVE  : $src -> $dst"
  mv "$src" "$dst"
}

safe_create_if_missing() {
  local dst="$1"
  local content="$2"

  if [ -e "$dst" ]; then
    echo "SKIP  : $dst existe déjà"
    return 0
  fi

  mkdir -p "$(dirname "$dst")"
  echo "CREATE: $dst"
  cat > "$dst" <<EOF
$content
EOF
}

echo
echo "==> Déplacement de l'existant"

safe_move "$SRC_DIR/api/assets.js" \
          "$SRC_DIR/features/assets/api/assetsApi.js"

safe_move "$SRC_DIR/components/assets/AssetsTable.jsx" \
          "$SRC_DIR/features/assets/components/AssetsTable.jsx"

safe_move "$SRC_DIR/pages/AssetsPage.jsx" \
          "$SRC_DIR/features/assets/pages/AssetsPage.jsx"

safe_move "$SRC_DIR/App.jsx" \
          "$SRC_DIR/app/App.jsx"

echo
echo "==> Création du socle minimal"

safe_create_if_missing \
  "$SRC_DIR/core/api/client.js" \
'const API_BASE_URL = "http://127.0.0.1:8000";

export async function apiGet(path) {
  const response = await fetch(`${API_BASE_URL}${path}`);

  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }

  return response.json();
}
'

safe_create_if_missing \
  "$SRC_DIR/core/layout/AppShell.jsx" \
'export default function AppShell({ children }) {
  return (
    <div style={{ padding: "24px" }}>
      <header style={{ marginBottom: "24px" }}>
        <h1>Specula Console</h1>
      </header>
      <main>{children}</main>
    </div>
  );
}
'

safe_create_if_missing \
  "$SRC_DIR/modules/.gitkeep" \
''

echo
echo "==> Vérification / création de src/app/App.jsx"

if [ ! -f "$SRC_DIR/app/App.jsx" ]; then
  cat > "$SRC_DIR/app/App.jsx" <<'EOF'
import AppShell from "../core/layout/AppShell";
import AssetsPage from "../features/assets/pages/AssetsPage";

export default function App() {
  return (
    <AppShell>
      <AssetsPage />
    </AppShell>
  );
}
EOF
  echo "CREATE: $SRC_DIR/app/App.jsx"
else
  echo "SKIP  : $SRC_DIR/app/App.jsx existe déjà"
fi

echo
echo "==> Mise à jour prudente de src/main.jsx"

if [ -f "$SRC_DIR/main.jsx" ]; then
  cp "$SRC_DIR/main.jsx" "$SRC_DIR/main.jsx.bak.${TS}"

  python3 <<'PY'
from pathlib import Path

path = Path("src/main.jsx")
content = path.read_text(encoding="utf-8")

content = content.replace('from "./App"', 'from "./app/App"')
content = content.replace("from './App'", "from './app/App'")

path.write_text(content, encoding="utf-8")
print("PATCH : src/main.jsx")
PY
else
  echo "SKIP  : src/main.jsx absent"
fi

echo
echo "==> Rappel important"
echo "Les imports internes des fichiers déplacés peuvent encore pointer vers les anciens chemins."
echo "Il faudra vérifier au minimum :"
echo " - src/features/assets/pages/AssetsPage.jsx"
echo " - src/features/assets/components/AssetsTable.jsx"
echo " - src/app/App.jsx"

echo
echo "==> Migration terminée"