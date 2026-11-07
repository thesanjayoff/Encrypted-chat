import type { ReactElement } from "react";
import { Link } from "react-router-dom";
import AuthCard, { primaryButtonClass, secondaryButtonClass } from "../components/AuthCard.js";

export default function WelcomePage(): ReactElement {
  return (
    <AuthCard title="Welcome" subtitle="End-to-end encrypted chat. Your keys never leave this device.">
      <div className="space-y-3">
        <Link to="/register" className={primaryButtonClass + " block text-center"}>
          Create an account
        </Link>
        <Link to="/link" className={secondaryButtonClass + " block text-center"}>
          Link this device to an existing account
        </Link>
      </div>
      <p className="mt-6 text-xs text-slate-400 dark:text-slate-500">
        This is a learning / portfolio project. It has not been professionally audited — see the README before trusting it with anything sensitive.
      </p>
    </AuthCard>
  );
}
