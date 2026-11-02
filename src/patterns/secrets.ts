// Comprehensive API-key / secret regex library.
// Each entry: a name, a regex, severity, and an optional "near" context word that
// must appear within ~60 chars of the match to reduce false positives on generic shapes.

export interface SecretPattern {
  name: string;
  re: RegExp;
  severity: "high" | "medium" | "low";
  near?: RegExp; // optional context word required nearby
  group?: number; // which capture group holds the actual secret
}

export const SECRET_PATTERNS: SecretPattern[] = [
  // ---- AWS ----
  { name: "AWS Access Key", re: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high" },
  { name: "AWS Session Access Key", re: /\bASIA[0-9A-Z]{16}\b/g, severity: "high" },
  { name: "AWS MWS Auth Token", re: /\bamzn\.mws\.[0-9a-f-]{36}\b/g, severity: "high" },
  { name: "AWS Secret Key (keyed)", re: /aws[_\- ]?(?:secret|access)?[_\- ]?key[^"'`\n]{0,20}["'`]([A-Za-z0-9/+=]{40})["'`]/gi, severity: "high", group: 1 },

  // ---- Google / Firebase ----
  { name: "Google API Key", re: /\bAIza[0-9A-Za-z_\-]{35}\b/g, severity: "high" },
  { name: "Google OAuth Client", re: /\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b/g, severity: "medium" },
  { name: "Google OAuth Access Token", re: /\bya29\.[0-9A-Za-z_\-]{20,}\b/g, severity: "high" },
  { name: "Google Service Account JSON", re: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"/g, severity: "high" },
  { name: "Firebase Cloud Messaging", re: /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,170}\b/g, severity: "high" },
  { name: "Firebase URL", re: /https:\/\/[\w-]+\.firebaseio\.com/g, severity: "medium" },

  // ---- Stripe ----
  { name: "Stripe Live Secret", re: /\bsk_live_[0-9a-zA-Z]{24,99}\b/g, severity: "high" },
  { name: "Stripe Live Publishable", re: /\bpk_live_[0-9a-zA-Z]{24,99}\b/g, severity: "low" },
  { name: "Stripe Restricted Key", re: /\brk_live_[0-9a-zA-Z]{24,99}\b/g, severity: "high" },
  { name: "Stripe Test Secret", re: /\bsk_test_[0-9a-zA-Z]{24,99}\b/g, severity: "medium" },
  { name: "Stripe Webhook Secret", re: /\bwhsec_[A-Za-z0-9/+]{32,80}\b/g, severity: "high" },

  // ---- GitHub / GitLab / Bitbucket ----
  { name: "GitHub Classic PAT", re: /\bghp_[0-9A-Za-z]{36}\b/g, severity: "high" },
  { name: "GitHub Fine-grained PAT", re: /\bgithub_pat_[A-Za-z0-9_]{70,100}\b/g, severity: "high" },
  { name: "GitHub OAuth Token", re: /\bgho_[0-9A-Za-z]{36}\b/g, severity: "high" },
  { name: "GitHub User Token", re: /\bghu_[0-9A-Za-z]{36}\b/g, severity: "high" },
  { name: "GitHub Server Token", re: /\bghs_[0-9A-Za-z]{36}\b/g, severity: "high" },
  { name: "GitHub Refresh Token", re: /\bghr_[0-9A-Za-z]{36}\b/g, severity: "high" },
  { name: "GitLab PAT", re: /\bglpat-[0-9A-Za-z_\-]{20}\b/g, severity: "high" },
  { name: "GitLab Pipeline Trigger", re: /\bglptt-[0-9a-f]{40}\b/g, severity: "high" },
  { name: "Bitbucket App Password", re: /\bATBB[A-Za-z0-9]{32}[A-Za-z0-9]{8}\b/g, severity: "high" },

  // ---- Slack / Discord / Telegram / Teams ----
  { name: "Slack Bot/User Token", re: /\bxox[baprs]-\d+-\d+-[0-9A-Za-z]+\b/g, severity: "high" },
  { name: "Slack App Token", re: /\bxapp-\d+-[A-Z0-9]+-\d+-[0-9a-f]{64}\b/g, severity: "high" },
  { name: "Slack Webhook", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g, severity: "medium" },
  { name: "Discord Bot Token", re: /\b[MN][A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,}\b/g, severity: "high" },
  { name: "Discord Webhook", re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g, severity: "medium" },
  { name: "Telegram Bot Token", re: /\b\d{8,10}:AA[A-Za-z0-9_-]{32,35}\b/g, severity: "high" },
  { name: "Microsoft Teams Webhook", re: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9-]+@[a-z0-9-]+\/IncomingWebhook\/[a-z0-9]+\/[a-z0-9-]+/g, severity: "medium" },
  { name: "Zapier Webhook", re: /https:\/\/hooks\.zapier\.com\/hooks\/catch\/\d+\/[a-zA-Z0-9]+/g, severity: "medium" },

  // ---- Comm / Email ----
  { name: "Twilio Account SID", re: /\bAC[a-f0-9]{32}\b/g, severity: "medium" },
  { name: "Twilio Auth Token", re: /\b[a-f0-9]{32}\b/g, severity: "medium", near: /twilio/i },
  { name: "Twilio API Key", re: /\bSK[a-f0-9]{32}\b/g, severity: "high" },
  { name: "Mailgun API Key", re: /\bkey-[0-9a-zA-Z]{32}\b/g, severity: "high" },
  { name: "Mailchimp API Key", re: /\b[0-9a-f]{32}-us\d{1,2}\b/g, severity: "high" },
  { name: "SendGrid API Key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "high" },
  { name: "Postmark Server Token", re: /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g, severity: "medium", near: /postmark/i },

  // ---- Payments ----
  { name: "PayPal Access Token", re: /access_token\$production\$[a-z0-9]{16,}\$[a-f0-9]{32}/g, severity: "high" },
  { name: "Square Access", re: /\bsq0(?:atp|csp|idp)-[0-9A-Za-z_\-]{22,}\b/g, severity: "high" },
  { name: "Braintree Access Token", re: /\baccess_token\$(?:sandbox|production)\$[0-9a-z]+\$[0-9a-f]{32}\b/g, severity: "high" },

  // ---- SaaS platforms ----
  { name: "Shopify Access Token", re: /\bshpat_[a-fA-F0-9]{32}\b/g, severity: "high" },
  { name: "Shopify Shared Secret", re: /\bshpss_[a-fA-F0-9]{32}\b/g, severity: "high" },
  { name: "Shopify Priv-App Token", re: /\bshppa_[a-fA-F0-9]{32}\b/g, severity: "high" },
  { name: "Shopify Custom-App Token", re: /\bshpca_[a-fA-F0-9]{32}\b/g, severity: "high" },
  { name: "Dropbox Access Token", re: /\bsl\.[A-Za-z0-9_-]{130,180}\b/g, severity: "high" },
  { name: "Heroku API Key", re: /heroku[^\n]{0,25}[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, severity: "high" },
  { name: "DigitalOcean PAT", re: /\bdop_v1_[a-f0-9]{64}\b/g, severity: "high" },
  { name: "DigitalOcean Refresh", re: /\bdor_v1_[a-f0-9]{64}\b/g, severity: "high" },
  { name: "DigitalOcean OAuth", re: /\bdoo_v1_[a-f0-9]{64}\b/g, severity: "high" },

  // ---- AI providers ----
  { name: "OpenAI Project Key", re: /\bsk-proj-[A-Za-z0-9_\-]{40,}\b/g, severity: "high" },
  { name: "OpenAI User Key", re: /\bsk-[A-Za-z0-9]{32,100}\b/g, severity: "high" },
  { name: "Anthropic API Key", re: /\bsk-ant-(?:api\d{2}|admin\d{2})-[A-Za-z0-9_\-]{80,}\b/g, severity: "high" },
  { name: "Hugging Face Token", re: /\bhf_[A-Za-z0-9]{34,40}\b/g, severity: "high" },
  { name: "Mistral API Key", re: /\b[A-Za-z0-9]{32}\b/g, severity: "medium", near: /mistral/i },
  { name: "Cohere API Key", re: /\b[A-Za-z0-9]{40}\b/g, severity: "medium", near: /cohere/i },
  { name: "Replicate Token", re: /\br8_[A-Za-z0-9]{37}\b/g, severity: "high" },

  // ---- Maps / monitoring ----
  { name: "Mapbox Secret Token", re: /\bsk\.ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, severity: "high" },
  { name: "Mapbox Public Token", re: /\bpk\.ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b/g, severity: "medium" },
  { name: "Sentry DSN", re: /https:\/\/[0-9a-f]{32}@[\w.]+\/\d+/g, severity: "medium" },
  { name: "Datadog API Key", re: /\b[a-f0-9]{32}\b/g, severity: "medium", near: /datadog|dd[-_]?api[-_]?key/i },
  { name: "New Relic User Key", re: /\bNRAK-[A-Z0-9]{27}\b/g, severity: "high" },
  { name: "New Relic Admin", re: /\bNRAA-[A-Z0-9]{27}\b/g, severity: "high" },
  { name: "New Relic REST", re: /\bNRRA-[A-Z0-9]{27}\b/g, severity: "high" },
  { name: "New Relic License", re: /\b[a-f0-9]{40}\b/g, severity: "medium", near: /new[-_ ]?relic/i },
  { name: "PagerDuty Token", re: /\b[a-zA-Z0-9+_\-]{20,32}\b/g, severity: "medium", near: /pagerduty/i },

  // ---- Package registries ----
  { name: "NPM Token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "high" },
  { name: "PyPI Token", re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{130,}\b/g, severity: "high" },
  { name: "RubyGems Token", re: /\brubygems_[a-f0-9]{48}\b/g, severity: "high" },
  { name: "Docker Hub PAT", re: /\bdckr_pat_[A-Za-z0-9_\-]{27}\b/g, severity: "high" },

  // ---- Infra / deploy ----
  { name: "Pulumi Access Token", re: /\bpul-[a-f0-9]{40}\b/g, severity: "high" },
  { name: "Vercel Token", re: /\b[A-Za-z0-9]{24}\b/g, severity: "medium", near: /vercel/i },
  { name: "Netlify Token", re: /\b(?:nf[a-zA-Z0-9]{25,}|[a-f0-9]{40,64})\b/g, severity: "medium", near: /netlify/i },
  { name: "Cloudflare API Token", re: /\b[A-Za-z0-9_\-]{40}\b/g, severity: "medium", near: /cloudflare|cf[-_]?api[-_]?token/i },
  { name: "Cloudflare Global Key", re: /\bv1\.0-[A-Za-z0-9_\-]{40,}\b/g, severity: "high" },
  { name: "Supabase Service Role (JWT)", re: /\beyJhbGciOiJIUzI1NiIs[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\b/g, severity: "high", near: /supabase|service_role/i },
  { name: "Terraform Cloud Token", re: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{40,}\b/g, severity: "high" },

  // ---- Social ----
  { name: "Twitter Bearer Token", re: /\bAAAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9_%]{10,}\b/g, severity: "high" },
  { name: "Facebook Access Token", re: /\bEAAC[0-9A-Za-z]{150,}\b/g, severity: "high" },
  { name: "LinkedIn Secret", re: /linkedin[^\n]{0,20}["']([A-Za-z0-9]{16})["']/gi, severity: "medium" },

  // ---- Generic / high-signal shapes ----
  { name: "JWT", re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, severity: "medium" },
  { name: "PEM Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |)PRIVATE KEY-----/g, severity: "high" },
  { name: "PGP Private Key", re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, severity: "high" },
  { name: "Age Secret Key", re: /\bAGE-SECRET-KEY-1[A-Z0-9]{58}\b/g, severity: "high" },
  { name: "SSH Private key (opened)", re: /ssh-(?:rsa|ed25519|dss) AAAA[A-Za-z0-9+/=]{100,}/g, severity: "low" },
  { name: "Basic Auth in URL", re: /https?:\/\/[A-Za-z0-9._~\-]+:[^@\s"'`<>]+@[^\s"'`<>]+/g, severity: "high" },
  { name: "DB connection string (creds)", re: /(?:jdbc:)?(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)[a-z]*:\/\/[^:/\s]+:[^@\s"'`<>]+@[^\s"'`<>]+/gi, severity: "high" },

  // ---- Context-driven: variable-name near value ----
  { name: "Secret-named variable", re: /(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|bearer[_-]?token|client[_-]?secret|session[_-]?secret|encryption[_-]?key|signing[_-]?key|master[_-]?key)[\s]*[:=][\s]*["']([A-Za-z0-9+/=_\-\.]{16,})["']/gi, severity: "high", group: 1 },
  { name: "Password-named variable", re: /(?:password|passwd|pwd|secret)[\s]*[:=][\s]*["']([^"'\s]{6,120})["']/gi, severity: "medium", group: 1 },

  // ---- Env-style ----
  { name: "Env-style secret", re: /(?:^|\n)\s*(?:export\s+)?([A-Z][A-Z0-9_]{3,30}(?:KEY|TOKEN|SECRET|PASSWORD|PWD|DSN))\s*=\s*["']?([^"'\n\s]{10,})["']?/g, severity: "high", group: 2 },
];

// Shannon entropy — returns bits per character
export function entropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let e = 0;
  for (const n of Object.values(freq)) { const p = n / s.length; e -= p * Math.log2(p); }
  return e;
}

export function looksLikeTestOrPlaceholder(value: string): boolean {
  const v = value.toLowerCase();
  return /example|placeholder|yourkey|xxxxx|<[a-z_]+>|change[_-]?me|dummy/i.test(v) ||
    /^(.)\1{5,}$/.test(v) || // same char repeated
    v === "aaaaaaaaaaaaaaaaa" ||
    v.startsWith("test_") ||
    v.includes("fakekey");
}
