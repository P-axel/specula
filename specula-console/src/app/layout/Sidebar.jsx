import { NavLink } from "react-router-dom";

const navItems = [
  { label: "Dashboard", to: "/" },
  {label: "Incidents", to: "/incidents"},
  { label: "Assets", to: "/assets" },
 
];

export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <h2>Specula</h2>
        <span>Console SOC</span>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              isActive ? "nav-item active" : "nav-item"
            }
          >
            {item.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}