import "./global.css";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import AppContent from "./components/AppContent";
import ErrorBoundary from "./components/ErrorBoundary";
import { setupAuthDebug } from "./utils/auth-debug";
import "./utils/auth-test"; // Import auth test utilities

const queryClient = new QueryClient();

// Setup auth debugging utilities in development
setupAuthDebug();

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>
            <AppContent />
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
