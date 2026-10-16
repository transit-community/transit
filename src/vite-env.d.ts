/// <reference types="vite/client" />

// Vite's client-side ambient types. Brings `import.meta.env.DEV`,
// `import.meta.env.PROD`, etc. into scope for the app code.
// `EnrollSecretDialog` reads `import.meta.env.DEV` to gate a
// dev-only affordance; without this reference, `tsc -b` fails on
// "Property 'env' does not exist on type 'ImportMeta'".
