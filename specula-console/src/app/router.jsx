import { createBrowserRouter } from "react-router-dom";
import AppShell from "./layout/AppShell";
import { SocDataProvider } from "../shared/providers/SocDataProvider";

import DashboardPage from "../features/dashboard/pages/DashboardPage";
import AssetsPage from "../features/assets/pages/AssetsPage";
import AssetDetail from "../features/assets/pages/AssetDetail";
import Incidents from "../features/incidents/pages/Incidents";
import IncidentInvestigation from "../features/incidents/pages/IncidentInvestigation";

export const router = createBrowserRouter([
  {
    path: "/",
    element: (
      <SocDataProvider>
        <AppShell />
      </SocDataProvider>
    ),
    children: [
      {
        index: true,
        element: <DashboardPage />,
      },
      {
        path: "assets",
        element: <AssetsPage />,
      },
      {
        path: "assets/:id",
        element: <AssetDetail />,
      },
      {
        path: "incidents",
        element: <Incidents />,
      },
      {
        path: "incidents/:id",
        element: <IncidentInvestigation />,
      },
    ],
  },
]);