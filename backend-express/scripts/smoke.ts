import { AuthService } from "../services/authService";
import { EmailService } from "../services/emailService";
import { daoStorage } from "../data/daoStorage";
import { NotificationService } from "../services/notificationService";

async function run() {
  try {
    console.log("Starting smoke tests...");

    // Ensure AuthService initialized
    await AuthService.initialize();

    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;

    if (!adminEmail || !adminPassword) {
      console.warn(
        "ADMIN_EMAIL or ADMIN_PASSWORD not set - skipping auth tests",
      );
    } else {
      console.log(`Attempting login as ${adminEmail}...`);
      const authResp = await AuthService.login({
        email: adminEmail,
        password: adminPassword,
      });
      if (!authResp) throw new Error("Login failed");
      console.log("Login OK, token length:", authResp.token.length);

      const verified = await AuthService.verifyToken(authResp.token);
      if (!verified) throw new Error("Token verification failed");
      console.log("Token verified for:", verified.email);

      // Test /me via service
      const me = await AuthService.getCurrentUser(authResp.token);
      console.log("AuthService.getCurrentUser returned:", me?.email);

      // Use admin to call reset via service functions
      console.log("Performing runtime cleanup via services...");
      daoStorage.clearAll(false);
      NotificationService.clearAll();
      await AuthService.clearAllSessions();
      await AuthService.reinitializeUsers();
      console.log("Runtime cleanup executed");
    }

    // DAO storage check
    console.log("DAO storage size:", daoStorage.size());

    // Email test (non-blocking)
    try {
      const smtpResult = await EmailService.sendNotificationEmail(
        adminEmail || "no-reply@example.com",
        "Smoketest",
        "If you receive this, the mailer path is working.",
      );
      console.log("Email send result:", smtpResult);
    } catch (e) {
      console.warn("Email test failed:", (e as Error).message);
    }

    console.log("Smoke tests completed successfully");
    process.exit(0);
  } catch (e) {
    console.error("Smoke tests failed:", (e as Error).message);
    process.exit(2);
  }
}

run();
