import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { testFetchFunctionality } from "@/utils/fetch-test";

export default function FetchTestButton() {
  const [testResult, setTestResult] = useState<string>("");
  const [isLoading, setIsLoading] = useState(false);

  const handleTest = async () => {
    setIsLoading(true);
    setTestResult("Testing...");

    try {
      const result = await testFetchFunctionality();
      if (result.success) {
        setTestResult("✅ Fetch test successful! Check console for details.");
      } else {
        setTestResult(`❌ Fetch test failed: ${result.error}`);
      }
    } catch (error) {
      setTestResult(
        `❌ Test error: ${error instanceof Error ? error.message : "Unknown"}`,
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Only show in development
  if (process.env.NODE_ENV !== "development") {
    return null;
  }

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2">
      <Button
        onClick={handleTest}
        disabled={isLoading}
        variant="outline"
        size="sm"
        className="bg-white shadow-lg"
      >
        {isLoading ? "Testing..." : "🧪 Test Fetch"}
      </Button>

      {testResult && (
        <Alert className="max-w-xs">
          <AlertDescription className="text-xs">{testResult}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
