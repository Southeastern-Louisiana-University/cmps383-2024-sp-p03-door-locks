import "./index.css";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Home from "./routes/index";
import { CachePolicies, Provider } from "use-http";
import LockScanner from "./routes/LockScanner";
import EnrollExample from "./routes/EnrollExample";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Home />,
  },
  {
    path: "/lock-scanner",
    element: <LockScanner />,
  },
  { path: "/enroll-example", element: <EnrollExample /> },
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <Provider options={{ cache: CachePolicies.NO_CACHE }}>
    <RouterProvider router={router} />
  </Provider>
);
