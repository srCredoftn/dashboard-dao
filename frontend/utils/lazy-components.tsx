import { lazy, Suspense, ComponentType } from 'react';
import { Loader2 } from 'lucide-react';

// Loading component for suspense fallback
export function PageLoadingSpinner() {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <div className="flex flex-col items-center space-y-4">
        <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
        <p className="text-sm text-gray-600">Chargement...</p>
      </div>
    </div>
  );
}

// HOC to wrap lazy components with suspense
export function withSuspense<P extends object>(
  LazyComponent: ComponentType<P>
): ComponentType<P> {
  return function SuspenseWrapper(props: P) {
    return (
      <Suspense fallback={<PageLoadingSpinner />}>
        <LazyComponent {...props} />
      </Suspense>
    );
  };
}

// Lazy loaded pages
export const LazyIndex = withSuspense(lazy(() => import('@/pages/Index')));
export const LazyDaoDetail = withSuspense(lazy(() => import('@/pages/DaoDetail')));
export const LazyAdminUsers = withSuspense(lazy(() => import('@/pages/AdminUsers')));
export const LazyProfile = withSuspense(lazy(() => import('@/pages/Profile')));
export const LazyUserManagement = withSuspense(lazy(() => import('@/pages/UserManagement')));

// Auth pages (can be loaded immediately as they're entry points)
export const LazyLogin = withSuspense(lazy(() => import('@/pages/Login')));
export const LazyForgotPassword = withSuspense(lazy(() => import('@/pages/ForgotPassword')));
export const LazyResetPassword = withSuspense(lazy(() => import('@/pages/ResetPassword')));

// Heavy components that can be lazy loaded
export const LazyGlobalExportDialog = withSuspense(
  lazy(() => import('@/components/GlobalExportDialog'))
);

// Loading states for smaller components
export function ComponentLoadingSpinner() {
  return (
    <div className="flex items-center justify-center p-4">
      <Loader2 className="h-5 w-5 animate-spin text-gray-400" />
    </div>
  );
}

// Lightweight suspense wrapper for smaller components
export function withLightSuspense<P extends object>(
  LazyComponent: ComponentType<P>
): ComponentType<P> {
  return function LightSuspenseWrapper(props: P) {
    return (
      <Suspense fallback={<ComponentLoadingSpinner />}>
        <LazyComponent {...props} />
      </Suspense>
    );
  };
}
