// Add to Env interface:
ED25519_PUBLIC_KEY_PREVIOUS: string; // Optional: previous public key for rotation

// Update DbSettings to include feature flags:
export interface DbSettings {
  database_version: string;
  backend_version: string;
  minimum_app_version: string;
  token_version: number;
  maintenance_mode: number;
  allow_activation: number; // 0 or 1
  allow_verify: number;     // 0 or 1
}