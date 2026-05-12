/**
 * AuthForge — Microsoft Entra / Azure AD token analysis (shared/entra.js)
 *
 * Entra (Azure AD) tokens follow a documented but non-obvious shape: a typical
 * pentest involves decoding claims, mapping cryptic ids to friendly names,
 * judging privilege from `wids` / `roles` / `scp`, and running read-only recon
 * against Microsoft Graph with the captured token to confirm what the token
 * actually unlocks.
 *
 * This module concentrates everything AuthForge knows about Entra so the
 * popup can detect, classify, audit, and recon Microsoft tokens with one
 * import. All values are sourced from public Microsoft documentation —
 * nothing here is proprietary.
 */

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/**
 * Is this a Microsoft Entra / Azure AD token? Looks at multiple signals so
 * we catch v1 + v2 + B2C + government-cloud variants.
 */
export function isEntraToken(decoded) {
  if (!decoded?.payload) return false;
  const iss = decoded.payload.iss || '';
  if (
    iss.includes('login.microsoftonline.com') ||
    iss.includes('login.microsoftonline.us') ||  // GCC High
    iss.includes('login.microsoftonline.de') ||  // German cloud (legacy)
    iss.includes('login.partner.microsoftonline.cn') || // China
    iss.includes('sts.windows.net') ||
    iss.includes('login.windows.net') ||
    iss.includes('b2clogin.com')
  ) return true;
  // Backup: the `xms_tcdt` and `tid` claims are unique to Entra
  if (decoded.payload.xms_tcdt != null) return true;
  if (decoded.payload.tid && decoded.payload.aud && decoded.payload.iss) {
    // tid + aud + iss is a near-conclusive AAD shape
    return /^https?:\/\/[^/]+(\.windows\.net|microsoftonline\.com)/.test(iss);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Known Microsoft / Office365 first-party app IDs and resource URIs.
// When the token's `aud` is one of these, we substitute a friendly name.
// ---------------------------------------------------------------------------

export const KNOWN_AUDIENCES = {
  // First-party app IDs (constants across all tenants)
  '00000003-0000-0000-c000-000000000000': 'Microsoft Graph',
  '00000002-0000-0000-c000-000000000000': 'Azure AD Graph (deprecated)',
  '00000009-0000-0000-c000-000000000000': 'Power BI Service',
  '00000004-0000-0000-c000-000000000000': 'Skype for Business Online',
  '00000005-0000-0000-c000-000000000000': 'Microsoft Yammer',
  '0000000c-0000-0000-c000-000000000000': 'Microsoft App Access Panel',
  '0000000a-0000-0000-c000-000000000000': 'Microsoft Intune',
  '00000007-0000-0ff1-ce00-000000000000': 'Office 365 Exchange Online',
  '00000003-0000-0ff1-ce00-000000000000': 'Office 365 SharePoint Online',
  '0f698dd4-f011-4d23-a33e-b36416dcb1e6': 'Microsoft Office Authentication Broker',
  '1950a258-227b-4e31-a9cf-717495945fc2': 'Microsoft Azure PowerShell',
  '04b07795-8ddb-461a-bbee-02f9e1bf7b46': 'Microsoft Azure CLI',
  '9bc3ab49-b65d-410a-85ad-de819febfddc': 'SharePoint Online Client Extensibility',
  '00000006-0000-0ff1-ce00-000000000000': 'Microsoft Office 365 Portal',
  'cf36b471-5b44-428c-9ce7-313bf84528de': 'Microsoft Forms',
  '5e3ce6c0-2b1f-4285-8d4b-75ee78787346': 'Microsoft Teams Web Client',
  '1fec8e78-bce4-4aaf-ab1b-5451cc387264': 'Microsoft Teams Native Client',

  // Resource URIs (used in v1 tokens)
  'https://graph.microsoft.com': 'Microsoft Graph (resource URI)',
  'https://graph.windows.net': 'Azure AD Graph (deprecated, resource URI)',
  'https://outlook.office.com': 'Outlook / Exchange Online',
  'https://outlook.office365.com': 'Outlook / Exchange Online',
  'https://management.azure.com': 'Azure Resource Manager',
  'https://management.core.windows.net': 'Azure Service Management (classic)',
  'https://vault.azure.net': 'Azure Key Vault',
  'https://storage.azure.com': 'Azure Storage',
  'https://servicebus.azure.net': 'Azure Service Bus',
  'https://eventgrid.azure.net': 'Azure Event Grid',
  'https://api.loganalytics.io': 'Azure Log Analytics',
  'https://api.partnercenter.microsoft.com': 'Microsoft Partner Center',
  'https://teams.microsoft.com': 'Microsoft Teams',
  'https://api.powerbi.com': 'Power BI REST API',
  'https://analysis.windows.net/powerbi/api': 'Power BI Analysis Services',
  'https://dynamics.microsoft.com': 'Dynamics 365',
};

// ---------------------------------------------------------------------------
// Well-known role IDs (the `wids` claim).
// Source: docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference
// ---------------------------------------------------------------------------

export const WIDS = {
  '62e90394-69f5-4237-9190-012177145e10': { name: 'Global Administrator', risk: 'critical' },
  '194ae4cb-b126-40b2-bd5b-6091b380977d': { name: 'Security Administrator', risk: 'critical' },
  'fe930be7-5e62-47db-91af-98c3a49a38b1': { name: 'User Administrator', risk: 'high' },
  '729827e3-9c14-49f7-bb1b-9608f156bbb8': { name: 'Helpdesk Administrator', risk: 'high' },
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': { name: 'SharePoint Administrator', risk: 'high' },
  '69091246-20e8-4a56-aa4d-066075b2a7a8': { name: 'Exchange Administrator', risk: 'high' },
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': { name: 'Application Administrator', risk: 'critical' },
  '158c047a-c907-4556-b7ef-446551a6b5f7': { name: 'Cloud Application Administrator', risk: 'critical' },
  'e8611ab8-c189-46e8-94e1-60213ab1f814': { name: 'Privileged Role Administrator', risk: 'critical' },
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': { name: 'Privileged Authentication Administrator', risk: 'critical' },
  '966707d0-3269-4727-9be2-8c3a10f19b9d': { name: 'Password Administrator', risk: 'high' },
  '4d6ac14f-3453-41d0-bef9-a3e0c569773a': { name: 'License Administrator', risk: 'medium' },
  'c4e39bd9-1100-46d3-8c65-fb160da0071f': { name: 'Authentication Administrator', risk: 'high' },
  '88d8e3e3-8f55-4a1e-953a-9b9898b8876b': { name: 'Directory Readers', risk: 'low' },
  '5d6b6bb7-de71-4623-b4af-96380a352509': { name: 'Security Reader', risk: 'low' },
  'b0f54661-2d74-4c50-afa3-1ec803f12efe': { name: 'Billing Administrator', risk: 'medium' },
  '29232cdf-9323-42fd-ade2-1d097af3e4de': { name: 'Exchange Recipient Administrator', risk: 'medium' },
  '8329153b-31d0-4727-b945-745eb3bc5f31': { name: 'Domain Name Administrator', risk: 'high' },
  '892c5842-a9a6-463a-8041-72aa08ca3cf6': { name: 'Cloud Device Administrator', risk: 'medium' },
  '17315797-102d-40b4-93e0-432062caca18': { name: 'Compliance Administrator', risk: 'high' },
  '38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4': { name: 'Desktop Analytics Administrator', risk: 'low' },
  'a9ea8996-122f-4c74-9520-8edcd192826c': { name: 'Power Platform Administrator', risk: 'high' },
};

// ---------------------------------------------------------------------------
// Microsoft Graph scopes that confer broad privilege when consented.
// ---------------------------------------------------------------------------

export const HIGH_PRIV_SCOPES = new Set([
  'Directory.ReadWrite.All',
  'Directory.AccessAsUser.All',
  'AppRoleAssignment.ReadWrite.All',
  'RoleManagement.ReadWrite.Directory',
  'Application.ReadWrite.All',
  'Application.ReadWrite.OwnedBy',
  'User.ReadWrite.All',
  'User.ManageIdentities.All',
  'Group.ReadWrite.All',
  'GroupMember.ReadWrite.All',
  'Policy.ReadWrite.ConditionalAccess',
  'Policy.ReadWrite.AuthenticationMethod',
  'PrivilegedAccess.ReadWrite.AzureAD',
  'PrivilegedAccess.ReadWrite.AzureADGroup',
  'DeviceManagementConfiguration.ReadWrite.All',
  'DeviceManagementManagedDevices.ReadWrite.All',
  'Mail.ReadWrite',
  'Mail.Send',
  'Files.ReadWrite.All',
  'Sites.FullControl.All',
  'IdentityRiskEvent.ReadWrite.All',
  'EduRoster.ReadWrite.All',
  // Wildcard catch-alls
  'Directory.AccessAsUser.All',
  '.default',
]);

export const NOTABLE_SCOPES_READONLY = new Set([
  'Directory.Read.All',
  'User.Read.All',
  'Group.Read.All',
  'Application.Read.All',
  'AuditLog.Read.All',
  'Policy.Read.All',
  'RoleManagement.Read.Directory',
]);

// ---------------------------------------------------------------------------
// Analysis: turn a decoded JWT into a structured Entra summary
// ---------------------------------------------------------------------------

export function analyzeEntraToken(decoded) {
  const p = decoded?.payload || {};
  const h = decoded?.header || {};

  // Token type heuristics
  let tokenType = 'unknown';
  if (p.scp && p.idtyp !== 'app') tokenType = 'access (delegated)';
  else if (p.roles && p.idtyp === 'app') tokenType = 'access (app-only)';
  else if (p.roles && !p.scp) tokenType = 'access (app-only)';
  else if (p.scp) tokenType = 'access (delegated)';
  else if (p.nonce && p.aud) tokenType = 'id';

  // Tenant
  const tid = p.tid;
  const COMMON_TIDS = {
    'common': 'common (any tenant)',
    'organizations': 'organizations (any AAD tenant, no personal MSA)',
    'consumers': 'consumers (MSA only)',
    '9188040d-6c67-4c5b-b112-36a304b66dad': 'MSA (personal accounts)',
  };
  const multiTenant = !!COMMON_TIDS[tid];

  // Audience resolution
  const audiences = (Array.isArray(p.aud) ? p.aud : [p.aud]).filter(Boolean);
  const resources = audiences.map((a) => ({
    raw: a,
    friendly: KNOWN_AUDIENCES[a] || a,
  }));

  // Scopes / roles / wids
  const scopes = (p.scp || '').split(' ').filter(Boolean);
  const appRoles = Array.isArray(p.roles) ? p.roles : [];
  const directoryRoles = (Array.isArray(p.wids) ? p.wids : []).map((w) => ({
    id: w,
    info: WIDS[w] || { name: '(unknown role)', risk: 'info' },
  }));

  // Risk synthesis — bubble up the most significant findings first
  const risks = [];
  for (const w of directoryRoles) {
    if (w.info.risk === 'critical') {
      risks.push({ severity: 'critical', text: `Directory role: ${w.info.name}` });
    } else if (w.info.risk === 'high') {
      risks.push({ severity: 'high', text: `Directory role: ${w.info.name}` });
    }
  }
  for (const s of scopes) {
    if (HIGH_PRIV_SCOPES.has(s)) {
      risks.push({ severity: 'high', text: `High-privilege scope: ${s}` });
    }
  }
  for (const r of appRoles) {
    // App roles starting with "Admin." or containing "ReadWrite.All" are notable
    if (/(\.ReadWrite\.All|\.FullControl\.|^Admin\.|\.All$)/.test(r)) {
      risks.push({ severity: 'medium', text: `App role: ${r}` });
    }
  }
  if (p.idtyp === 'app') {
    risks.push({
      severity: 'medium',
      text: 'App-only token (client credentials flow) — no user context. ' +
        'These tokens act with the app\'s assigned permissions directly.',
    });
  }
  if (multiTenant) {
    risks.push({
      severity: 'medium',
      text: 'Multi-tenant audience — token issued via /' + tid + '/ endpoint, accepted by apps in any tenant.',
    });
  }
  if (scopes.includes('.default')) {
    risks.push({
      severity: 'info',
      text: '.default scope used — token carries every consented permission, not a subset.',
    });
  }

  // Authentication context
  const authMethods = Array.isArray(p.amr) ? p.amr : [];
  const hasMfa = authMethods.includes('mfa') || authMethods.includes('mfa');
  const acr = p.acr;

  return {
    isEntra: true,
    version: p.ver || (h.typ === 'JWT' && p.iss?.includes('sts.windows.net') ? '1.0' : '2.0'),
    tokenType,
    issuer: p.iss,
    issuedAt: p.iat ? new Date(p.iat * 1000) : null,
    expiresAt: p.exp ? new Date(p.exp * 1000) : null,
    notBefore: p.nbf ? new Date(p.nbf * 1000) : null,

    tenantId: tid,
    tenantLabel: COMMON_TIDS[tid] || tid,
    multiTenant,

    user: {
      oid: p.oid,
      sub: p.sub,
      upn: p.upn || p.preferred_username || p.unique_name || p.email,
      name: p.name || p.given_name,
      ipaddr: p.ipaddr,
    },

    app: {
      id: p.appid || p.azp,
      name: p.app_displayname,
      idtyp: p.idtyp || 'user',
    },

    resources,
    scopes,
    appRoles,
    directoryRoles,
    risks,

    auth: {
      acr,
      methods: authMethods,
      hasMfa,
    },
  };
}

// ---------------------------------------------------------------------------
// Microsoft Graph recon — read-only endpoints that pentesters routinely
// query against a captured token to enumerate what the principal can do.
// ---------------------------------------------------------------------------

/**
 * Recon endpoints, grouped by which Entra audience the token must have to
 * call them. An Entra access token is *audience-bound* — a token for the
 * Microsoft Graph audience cannot call the Outlook REST API and vice versa.
 * The UI filters this list to only the endpoints the captured token can
 * actually reach, so Outlook-issued tokens don't waste time hitting Graph
 * and returning 401.
 *
 * Each entry's `audiences` lists every audience claim (aud) value that
 * unlocks the endpoint. AuthForge matches case-insensitively against
 * both string and array aud claims.
 */
export const RECON_ENDPOINTS = [
  // ===========================================================================
  // Microsoft Graph — aud=00000003-0000-0000-c000-000000000000 OR
  //                       https://graph.microsoft.com
  // ===========================================================================
  {
    id: 'graph-me',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Current user (/me)',
    description: 'Identity behind the token: displayName, mail, jobTitle, mobilePhone, id.',
    url: 'https://graph.microsoft.com/v1.0/me',
    requires: 'User.Read',
    significance: 'baseline',
  },
  {
    id: 'graph-me-mfa',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'My MFA methods',
    description: 'Authentication methods registered for the user — phones, FIDO2, MS Authenticator. Disclosure-only.',
    url: 'https://graph.microsoft.com/v1.0/me/authentication/methods',
    requires: 'UserAuthenticationMethod.Read',
    significance: 'recon',
  },
  {
    id: 'graph-me-memberof',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'My direct group / role memberships',
    description: 'Groups and directory roles the user is a direct member of. Lots of these = high access.',
    url: 'https://graph.microsoft.com/v1.0/me/memberOf?$top=100',
    requires: 'User.Read',
    significance: 'recon',
  },
  {
    id: 'graph-me-transitive',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'My transitive memberships',
    description: 'Includes nested group memberships. Shows the full privilege lattice.',
    url: 'https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$top=100',
    requires: 'User.Read',
    significance: 'recon',
  },
  {
    id: 'graph-me-owned-objects',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Apps / groups I own',
    description: 'Application registrations and security groups the user owns — write access to these.',
    url: 'https://graph.microsoft.com/v1.0/me/ownedObjects',
    requires: 'User.Read',
    significance: 'recon',
  },
  {
    id: 'graph-users-list',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Enumerate users (top 10)',
    description: 'Lists tenant users. Succeeds with User.Read.All or admin context.',
    url: 'https://graph.microsoft.com/v1.0/users?$top=10',
    requires: 'User.Read.All',
    significance: 'priv-escalation',
  },
  {
    id: 'graph-groups-list',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Enumerate groups (top 10)',
    description: 'Lists tenant groups. Discloses group/role structure.',
    url: 'https://graph.microsoft.com/v1.0/groups?$top=10',
    requires: 'Group.Read.All',
    significance: 'priv-escalation',
  },
  {
    id: 'graph-apps-list',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Enumerate app registrations (top 10)',
    description: 'Lists registered applications. Strong privilege signal if it succeeds.',
    url: 'https://graph.microsoft.com/v1.0/applications?$top=10',
    requires: 'Application.Read.All',
    significance: 'priv-escalation',
  },
  {
    id: 'graph-service-principals',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Enumerate service principals (top 10)',
    description: 'Service principals in the tenant. Used to map app→permissions chains.',
    url: 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=10',
    requires: 'Application.Read.All',
    significance: 'priv-escalation',
  },
  {
    id: 'graph-directory-roles',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Active directory roles',
    description: 'Shows which directory roles are activated in the tenant.',
    url: 'https://graph.microsoft.com/v1.0/directoryRoles',
    requires: 'Directory.Read.All',
    significance: 'priv-escalation',
  },
  {
    id: 'graph-role-assignments',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Directory role assignments',
    description: 'Maps roles to principals. Quickly identifies admins.',
    url: 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$top=20',
    requires: 'RoleManagement.Read.Directory',
    significance: 'critical-recon',
  },
  {
    id: 'graph-conditional-access',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'Conditional Access policies',
    description: 'Lists CA policies. Reveals defences an attacker would route around.',
    url: 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies',
    requires: 'Policy.Read.All',
    significance: 'critical-recon',
  },
  {
    id: 'graph-me-drive',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'My OneDrive root',
    description: 'Top-level files in the user\'s OneDrive. Quickly hits sensitive docs.',
    url: 'https://graph.microsoft.com/v1.0/me/drive/root/children',
    requires: 'Files.Read',
    significance: 'data-access',
  },
  {
    id: 'graph-me-messages',
    audienceGroup: 'Microsoft Graph',
    audiences: ['00000003-0000-0000-c000-000000000000', 'https://graph.microsoft.com'],
    name: 'My latest emails (top 5)',
    description: 'Reads inbox via Graph. Sensitive — only run with permission.',
    url: 'https://graph.microsoft.com/v1.0/me/messages?$top=5&$select=subject,from,receivedDateTime',
    requires: 'Mail.Read',
    significance: 'data-access',
  },

  // ===========================================================================
  // Outlook REST API — aud=https://outlook.office.com or outlook.office365.com
  //
  // Same data Microsoft Graph exposes but via the legacy Outlook endpoint.
  // Outlook Web App tokens land here, NOT Graph — that's the typical pattern
  // when you extract a token from a mailbox session.
  // ===========================================================================
  {
    id: 'outlook-me',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'Current user (Outlook /me)',
    description: 'Mailbox owner identity via Outlook REST — works with the Outlook audience.',
    url: 'https://outlook.office.com/api/v2.0/me',
    requires: 'Mail-bound token',
    significance: 'baseline',
  },
  {
    id: 'outlook-folders',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'Mailbox folders',
    description: 'Top-level mailbox folders — Inbox, Sent Items, Drafts, custom labels.',
    url: 'https://outlook.office.com/api/v2.0/me/mailfolders',
    requires: 'Mail.Read',
    significance: 'recon',
  },
  {
    id: 'outlook-messages',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'My latest emails (top 5)',
    description: 'Reads inbox via Outlook REST. Sensitive — only run with permission.',
    url: 'https://outlook.office.com/api/v2.0/me/messages?$top=5&$select=Subject,From,ReceivedDateTime',
    requires: 'Mail.Read',
    significance: 'data-access',
  },
  {
    id: 'outlook-contacts',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'My contacts (top 10)',
    description: 'Personal contacts — display names, email addresses, phone numbers.',
    url: 'https://outlook.office.com/api/v2.0/me/contacts?$top=10&$select=DisplayName,EmailAddresses,BusinessPhones',
    requires: 'Contacts.Read',
    significance: 'data-access',
  },
  {
    id: 'outlook-calendar',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'My calendar (next 5 events)',
    description: 'Upcoming calendar events with attendees, locations, organizer.',
    url: 'https://outlook.office.com/api/v2.0/me/calendarview?startDateTime=' +
      encodeURIComponent(new Date().toISOString()) +
      '&endDateTime=' +
      encodeURIComponent(new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString()) +
      '&$top=5&$select=Subject,Organizer,Start,End,Attendees,Location',
    requires: 'Calendars.Read',
    significance: 'data-access',
  },
  {
    id: 'outlook-mailbox-settings',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'Mailbox settings',
    description: 'Time zone, working hours, auto-reply text. Useful for social-engineering recon.',
    url: 'https://outlook.office.com/api/v2.0/me/mailboxsettings',
    requires: 'MailboxSettings.Read',
    significance: 'recon',
  },
  {
    id: 'outlook-rules',
    audienceGroup: 'Outlook REST',
    audiences: ['https://outlook.office.com', 'https://outlook.office365.com', '00000002-0000-0ff1-ce00-000000000000'],
    name: 'Inbox rules',
    description: 'Server-side forwarding / filter rules. Adversaries love these for persistence.',
    url: 'https://outlook.office.com/api/v2.0/me/mailfolders/inbox/messagerules',
    requires: 'MailboxSettings.Read',
    significance: 'critical-recon',
  },

  // ===========================================================================
  // Azure Resource Manager (ARM) — aud=https://management.azure.com or
  //                                    https://management.core.windows.net
  // ===========================================================================
  {
    id: 'arm-subscriptions',
    audienceGroup: 'Azure Resource Manager',
    audiences: ['https://management.azure.com', 'https://management.core.windows.net', 'https://management.azure.com/'],
    name: 'My subscriptions',
    description: 'Azure subscriptions the user has any role on. Empty = no Azure roles.',
    url: 'https://management.azure.com/subscriptions?api-version=2022-12-01',
    requires: 'Reader on the subscription',
    significance: 'baseline',
  },
  {
    id: 'arm-tenants',
    audienceGroup: 'Azure Resource Manager',
    audiences: ['https://management.azure.com', 'https://management.core.windows.net', 'https://management.azure.com/'],
    name: 'Tenants list',
    description: 'Tenants the user is a guest or member of (cross-tenant recon).',
    url: 'https://management.azure.com/tenants?api-version=2022-12-01',
    requires: 'Any signed-in user',
    significance: 'recon',
  },
  {
    id: 'arm-providers',
    audienceGroup: 'Azure Resource Manager',
    audiences: ['https://management.azure.com', 'https://management.core.windows.net', 'https://management.azure.com/'],
    name: 'Resource providers',
    description: 'Registered Azure resource providers — discloses which Azure services are in use.',
    url: 'https://management.azure.com/providers?api-version=2022-12-01&$top=10',
    requires: 'Subscription Reader',
    significance: 'recon',
  },

  // ===========================================================================
  // Azure Key Vault — aud=https://vault.azure.net
  // ===========================================================================
  {
    id: 'kv-list',
    audienceGroup: 'Azure Key Vault',
    audiences: ['https://vault.azure.net'],
    name: 'List secrets (requires the vault hostname)',
    description: 'Key Vault tokens are vault-specific; the actual URL needs the {vault-name}. Use as a template.',
    url: 'https://YOUR-VAULT.vault.azure.net/secrets?api-version=7.4',
    requires: 'get/list permission on the vault',
    significance: 'data-access',
    isTemplate: true,
  },

  // ===========================================================================
  // SharePoint / OneDrive (per-tenant)
  // ===========================================================================
  {
    id: 'spo-web',
    audienceGroup: 'SharePoint Online',
    audiences: ['https://*.sharepoint.com', 'sharepoint.com'],
    name: 'Site web info (requires tenant URL)',
    description: 'Site-collection metadata. Substitute your tenant\'s host (e.g. contoso.sharepoint.com).',
    url: 'https://YOUR-TENANT.sharepoint.com/_api/web',
    requires: 'tenant SPO token',
    significance: 'recon',
    isTemplate: true,
  },
];

/**
 * Given a decoded token's audience claim, return the list of recon endpoints
 * it CAN actually reach. The matching is forgiving:
 *   - Case-insensitive
 *   - Strips trailing slashes
 *   - Supports wildcards in audience patterns (e.g. https://*.sharepoint.com)
 *   - Handles both string and array `aud` claims
 */
export function reconEndpointsForToken(decoded) {
  if (!decoded?.payload) return { matched: [], unmatched: [...RECON_ENDPOINTS] };
  const tokenAuds = []
    .concat(decoded.payload.aud || [])
    .map((a) => String(a || '').toLowerCase().replace(/\/+$/, ''));

  const matched = [];
  const unmatched = [];
  for (const ep of RECON_ENDPOINTS) {
    const ok = ep.audiences.some((pattern) =>
      audienceMatches(pattern.toLowerCase().replace(/\/+$/, ''), tokenAuds)
    );
    if (ok) matched.push(ep);
    else unmatched.push(ep);
  }
  return { matched, unmatched };
}

function audienceMatches(pattern, tokenAuds) {
  if (pattern.includes('*')) {
    // Wildcard: convert to a regex (only * supported, escape rest)
    const re = new RegExp(
      '^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]+') + '$'
    );
    return tokenAuds.some((a) => re.test(a));
  }
  return tokenAuds.includes(pattern);
}

// ---------------------------------------------------------------------------
// FOCI — Family of Client IDs
//
// Microsoft's first-party clients form an implicit refresh-token "family":
// a refresh token issued to any FOCI client can be redeemed for an access
// token belonging to any other FOCI client. This is the lateral-movement
// move that GraphSpy / ROADtools / TokenTactics exploit: capture an
// Outlook refresh token, swap it for a Graph access token, dump the
// directory; swap it again for an Azure CLI token, query subscriptions.
//
// Source: documented FOCI client IDs gathered from open-source M365
// research (Dirk-jan Mollema, secureworks, etc.). All client IDs are
// public constants — they appear in every Entra tenant.
// ---------------------------------------------------------------------------

export const FOCI_CLIENTS = [
  {
    id: 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    name: 'Microsoft Office',
    notes: 'The classic FOCI client. Use for general-purpose access tokens — wide scope.',
    suggestedScope: 'https://graph.microsoft.com/.default offline_access',
    targetService: 'Microsoft Graph',
  },
  {
    id: '00b41c95-dab0-4487-9791-b9d2c32c80f2',
    name: 'Office 365 Management',
    suggestedScope: 'https://manage.office.com/.default offline_access',
    targetService: 'Office 365 Management API',
  },
  {
    id: '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
    name: 'Microsoft Azure CLI',
    notes: 'Highly privileged in many tenants. Try this for ARM access.',
    suggestedScope: 'https://management.azure.com/.default offline_access',
    targetService: 'Azure Resource Manager',
  },
  {
    id: '1950a258-227b-4e31-a9cf-717495945fc2',
    name: 'Microsoft Azure PowerShell',
    suggestedScope: 'https://management.azure.com/.default offline_access',
    targetService: 'Azure Resource Manager',
  },
  {
    id: '1b730954-1685-4b74-9bfd-dac224a7b894',
    name: 'Azure Active Directory PowerShell',
    notes: 'AAD-specific. Pairs with Graph scopes for directory recon.',
    suggestedScope: 'https://graph.microsoft.com/.default offline_access',
    targetService: 'Microsoft Graph (AAD-centric)',
  },
  {
    id: '14d82eec-204b-4c2f-b7e8-296a70dab67e',
    name: 'Microsoft Graph PowerShell',
    suggestedScope: 'https://graph.microsoft.com/.default offline_access',
    targetService: 'Microsoft Graph',
  },
  {
    id: 'a40d7d7d-59aa-447e-a655-679a4107e548',
    name: 'Office UWP PWA',
    suggestedScope: 'https://outlook.office.com/.default offline_access',
    targetService: 'Outlook REST',
  },
  {
    id: '27922004-5251-4030-b22d-91ecd9a37ea4',
    name: 'Outlook Mobile',
    suggestedScope: 'https://outlook.office.com/.default offline_access',
    targetService: 'Outlook REST',
  },
  {
    id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
    name: 'Microsoft Teams (Native)',
    suggestedScope: 'https://api.spaces.skype.com/.default offline_access',
    targetService: 'Microsoft Teams',
  },
  {
    id: 'ab9b8c07-8f02-4f72-87fa-80105867a763',
    name: 'OneDrive iOS / SharePoint Online Client',
    suggestedScope: 'https://YOUR-TENANT.sharepoint.com/.default offline_access',
    targetService: 'SharePoint Online (per-tenant)',
    note: 'Scope needs your tenant hostname substituted.',
  },
  {
    id: 'b26aadf8-566f-4478-926f-589f601d9c74',
    name: 'OneDrive SyncEngine',
    suggestedScope: 'https://YOUR-TENANT-my.sharepoint.com/.default offline_access',
    targetService: 'OneDrive for Business',
    note: 'Scope needs your tenant hostname substituted.',
  },
  {
    id: '9bc3ab49-b65d-410a-85ad-de819febfddc',
    name: 'SharePoint Online Client Extensibility',
    suggestedScope: 'https://YOUR-TENANT.sharepoint.com/.default offline_access',
    targetService: 'SharePoint Online',
    note: 'Scope needs your tenant hostname substituted.',
  },
  {
    id: '0ec893e0-5785-4de6-99da-4ed124e5296c',
    name: 'Office UWP (Win10/11)',
    suggestedScope: 'https://outlook.office.com/.default offline_access',
    targetService: 'Outlook REST',
  },
];

/**
 * Detect whether a refresh token is likely a FOCI refresh token by looking
 * at the issuing client ID embedded in the associated access token. The
 * caller passes the access token's `appid` / `azp` claim.
 */
export function isLikelyFOCIClient(clientId) {
  if (!clientId) return false;
  return FOCI_CLIENTS.some((c) => c.id === clientId);
}

// ---------------------------------------------------------------------------
// Audience-confusion candidates — alternate resources to test a captured
// token against. If the server doesn't validate the audience strictly,
// the token may be accepted by an unintended resource.
// ---------------------------------------------------------------------------

export const AUDIENCE_CONFUSION_TARGETS = [
  { url: 'https://graph.microsoft.com/v1.0/$metadata', name: 'Microsoft Graph' },
  { url: 'https://outlook.office.com/api/v2.0/me', name: 'Outlook' },
  { url: 'https://management.azure.com/subscriptions?api-version=2020-01-01', name: 'Azure Resource Manager' },
  { url: 'https://vault.azure.net/secrets?api-version=7.4', name: 'Azure Key Vault' },
  { url: 'https://graph.windows.net/me?api-version=1.6', name: 'AAD Graph (legacy)' },
];
