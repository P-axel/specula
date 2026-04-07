import { useState, useEffect } from "react";
import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";
import CriticalAlertToast from "../../shared/ui/CriticalAlertToast";

const BOOT_LINES = [
  { text: "[SYS] Initializing neural interface ...", delay: 100,  tone: "" },
  { text: "[NET] Connecting to detection grid  ...", delay: 480,  tone: "" },
  { text: "[IDS] Suricata sensor online         ...", delay: 840,  tone: "ok" },
  { text: "[EDR] Wazuh endpoint monitor ready   ...", delay: 1180, tone: "ok" },
  { text: "[SOC] Loading threat correlation matrix", delay: 1480, tone: "" },
  { text: "[OK]  All systems nominal. Stand by.   ", delay: 1780, tone: "ok" },
];

function BootLine({ text, delay, tone }) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(t);
  }, [delay]);
  if (!visible) return null;
  return <div className={`boot-line boot-line--${tone}`}>{text}</div>;
}

function BootScreen() {
  return (
    <div className="boot-screen">
      <div className="boot-screen__scan" />
      <div className="boot-screen__logo">SPECULA</div>
      <div className="boot-screen__subtitle">Security Operations Center — Core v0.2.0</div>
      <div className="boot-screen__lines">
        {BOOT_LINES.map((l, i) => (
          <BootLine key={i} {...l} />
        ))}
      </div>
    </div>
  );
}

export default function AppShell() {
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setBooted(true), 2650);
    return () => clearTimeout(t);
  }, []);

  return (
    <>
      {!booted && <BootScreen />}
      <div className="app-shell">
        <Sidebar />
        <div className="app-main">
          <Header />
          <main className="app-content">
            <Outlet />
          </main>
        </div>
        <CriticalAlertToast />
      </div>
    </>
  );
}
