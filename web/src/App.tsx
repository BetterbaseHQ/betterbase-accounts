import { Routes, Route, Navigate } from "react-router-dom";
import { ErrorBoundary } from "@/components/error-boundary";
import { AuthProvider, useAuth } from "@/contexts/auth-context";
import { LoginPage } from "@/pages/login";
import { SignupPage } from "@/pages/signup";
import { ConsentPage } from "@/pages/consent";
import { RecoverySetupPage } from "@/pages/recovery-setup";
import { RecoverPage } from "@/pages/recover";
import { ChangePasswordPage } from "@/pages/change-password";

function HomePage() {
  const { authToken, userId, clearAuth } = useAuth();

  if (!authToken) {
    return <Navigate to="/login" replace />;
  }

  const handleLogout = () => {
    clearAuth();
    window.location.href = "/login";
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4 p-4">
      <h1 className="text-2xl font-bold">Welcome!</h1>
      <p className="text-muted-foreground">You are logged in as {userId}</p>
      <button
        onClick={handleLogout}
        className="rounded-md bg-primary px-4 py-2 text-primary-foreground hover:bg-primary/90"
      >
        Log out
      </button>
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/consent" element={<ConsentPage />} />
          <Route path="/recovery-setup" element={<RecoverySetupPage />} />
          <Route path="/recover" element={<RecoverPage />} />
          <Route path="/change-password" element={<ChangePasswordPage />} />
        </Routes>
      </AuthProvider>
    </ErrorBoundary>
  );
}

export default App;
