import { useEffect, useState, lazy, Suspense } from "react";

const LazyShadToaster = lazy(() =>
  import("@/components/ui/toaster").then((m) => ({ default: m.Toaster })),
);
const LazySonner = lazy(() =>
  import("@/components/ui/sonner").then((m) => ({ default: m.Toaster })),
);

export default function DeferredToasters() {
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const schedule = (cb: () => void) => {
      // Prefer requestIdleCallback when available to avoid jank
      if (typeof (window as any).requestIdleCallback === "function") {
        (window as any).requestIdleCallback(cb, { timeout: 2000 });
      } else {
        // Fallback: small delay after first paint
        setTimeout(cb, 300);
      }
    };

    // Defer mounting until idle
    schedule(() => setReady(true));

    // Also prefetch on first user interaction to ensure quick first toast
    const prefetch = () => {
      import("@/components/ui/toaster");
      import("@/components/ui/sonner");
      window.removeEventListener("pointerdown", prefetch);
      window.removeEventListener("keydown", prefetch);
    };
    window.addEventListener("pointerdown", prefetch, { once: true });
    window.addEventListener("keydown", prefetch, { once: true });

    return () => {
      window.removeEventListener("pointerdown", prefetch);
      window.removeEventListener("keydown", prefetch);
    };
  }, []);

  if (!ready) return null;

  return (
    <Suspense fallback={null}>
      <LazyShadToaster />
      <LazySonner />
    </Suspense>
  );
}
