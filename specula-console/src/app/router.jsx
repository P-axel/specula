import { createBrowserRouter } from "react-router-dom";
import AppShell from "./layout/AppShell";

import DashboardPage from "../features/dashboard/pages/DashboardPage";
import AssetsPage from "../features/assets/pages/AssetsPage";
import EventsPage from "../features/events/pages/EventsPage";
import DetectionsPage from "../features/detections/pages/DetectionsPage";
import NetworkPage from "../features/network/pages/NetworkPage";
import SocIncidentsPage from "../features/soc/pages/SocIncidentsPage";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
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
        path: "events",
        element: <EventsPage />,
      },
  
      {
        path: "detections",
        element: <DetectionsPage />,
      },
      {
        path: "network",
        element: <NetworkPage />,
      },
      {
        path: "incidents/soc",
        element: <SocIncidentsPage />,
      },
    ],
  },
]);