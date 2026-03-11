function StatusBadge({ status }) {
  const normalized = (status || "").toLowerCase();
  const className =
    normalized === "active"
      ? "status-badge status-active"
      : "status-badge status-default";

  return <span className={className}>{status || "unknown"}</span>;
}

export default function AssetsTable({ assets }) {
  if (!assets.length) {
    return (
      <div className="state-box">
        <p>Aucun asset trouvé.</p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="assets-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Nom</th>
            <th>Adresse IP</th>
            <th>Type</th>
            <th>OS</th>
            <th>Statut</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => (
            <tr key={asset.asset_id}>
              <td className="mono">{asset.asset_id}</td>
              <td className="asset-name-cell">
                <div className="asset-name">{asset.name}</div>
                <div className="asset-hostname">{asset.hostname}</div>
              </td>
              <td className="mono">{asset.ip_address}</td>
              <td>{asset.asset_type}</td>
              <td>
                {asset.os_name} {asset.os_version}
              </td>
              <td>
                <StatusBadge status={asset.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}