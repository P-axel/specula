import { createBrowserRouter } from "react-router-dom";
import AppShell from "./layout/AppShell";

import DashboardPage from "../features/dashboard/pages/DashboardPage";
import AssetsPage from "../features/assets/pages/AssetsPage";
import EventsPage from "../features/events/pages/EventsPage";
import AlertsPage from "../features/alerts/pages/AlertsPage";
import DetectionsPage from "../features/detections/pages/DetectionsPage";

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
        path: "alerts",
        element: <AlertsPage />,
      },
      {
        path: "detections",
        element: <DetectionsPage />,
      },
    ],
  },
]);