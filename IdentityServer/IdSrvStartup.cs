﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using IdentityServer.Services;
using IdentityServer3.Core;
using IdentityServer3.Core.Configuration;
using IdentityServer3.Core.Events;
using IdentityServer3.Core.Models;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Services.Default;
using IdentityServer3.Core.Services.InMemory;
using IdentityServer3.Core.Validation;
using Microsoft.Owin;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Twitter;
using Owin;

[assembly: OwinStartup(typeof(IdentityServer.IdSrvStartup))]

namespace IdentityServer
{
    public class IdSrvStartup
    {
        private static readonly List<Client> Clients = new List<Client>
        {
            #region Server Applications

            new Client
            {
                ClientId = "god",
                ClientSecrets = { new Secret("secret") },
                Flow = Flows.ClientCredentials,
                AccessTokenLifetime = 1800,
                PrefixClientClaims = false,
                AlwaysSendClientClaims = true,
                AllowAccessToAllScopes = true,
                Claims =
                {
                    new Claim("is_god", true.ToString(), ClaimValueTypes.Boolean),
                    new Claim("api_filestore:read", "allow"),
                    new Claim("api_filestore:unrestricted_read", "allow"),
                    new Claim("api_filestore:store", "allow")
                }
            },

            new Client
            {
                ClientId = "api_cv_profile",
                ClientSecrets = { new Secret("secret") },
                Flow = Flows.Custom,
                AllowedCustomGrantTypes = { "delegation" },
                PrefixClientClaims = false,
                AlwaysSendClientClaims = true,
                AllowedScopes = 
                {
                    "api_filestore", "openid"
                },
                Claims =
                {
                    new Claim("api_filestore:read", "allow"),
                    new Claim("api_filestore:store", "allow")
                }
            },

            #endregion

            #region Websites
            
            new Client
            {
                ClientId = "website1",
                ClientName = "Demo WebSite #1",
                ClientUri = "http://website1.sso/",
                Flow = Flows.Implicit,
                RedirectUris = new List<string> { "http://website1.sso/" },
                PostLogoutRedirectUris = new List<string> { "http://website1.sso/" },
                LogoutUri = "http://website1.sso/Home/OidcSignOut",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                PrefixClientClaims = false,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    "dummy"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = false,
                AllowRememberConsent = true,
            },
            new Client
            {
                ClientId = "website2",
                ClientName = "Demo WebSite #2",
                ClientUri = "http://website2.sso/",
                Flow = Flows.Implicit,
                RedirectUris = new List<string> { "http://website2.sso/" },
                PostLogoutRedirectUris = new List<string> { "http://website2.sso/" },
                LogoutUri = "http://website2.sso/Home/OidcSignOut",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId
                },
                RequireConsent = false,
                AllowRememberConsent = true,
            },
            new Client
            {
                ClientId = "website3",
                ClientSecrets = { new Secret("secret") },
                ClientName = "Demo WebSite #3",
                ClientUri = "http://website3.sso/",
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://website3.sso/" },
                PostLogoutRedirectUris = new List<string> { "http://website3.sso/" },
                LogoutUri = "http://website3.sso/Home/OidcSignOut",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AuthorizationCodeLifetime = 10,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                PrefixClientClaims = false,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Roles,
                    Constants.StandardScopes.Profile
                },
                AlwaysSendClientClaims = true,
                RequireConsent = false,
                AllowRememberConsent = true,
            },
            new Client
            {
                ClientId = "website4",
                ClientName ="Demo Website #4",
                ClientUri = "http://website4.sso/",
                Flow = Flows.Implicit,
                RedirectUris = new List<string> { "http://website4.sso/index.html", "http://website4.sso/silent-renew.html" },
                PostLogoutRedirectUris = new List<string> { "http://website4.sso/index.html" },
                AllowedCorsOrigins = new List<string> { "http://website4.sso" },
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.Email,
                    "api_cv_profile"
                },
                AlwaysSendClientClaims = true,
                PrefixClientClaims = false,
                Claims =
                {
                    new Claim("api_cv_profile:read", "allow"),
                    new Claim("api_cv_profile:write", "allow")
                },
                RequireConsent = false,
                AllowRememberConsent = true,
                IncludeJwtId = true
            },
            new Client
            {
                ClientId = "website5",
                ClientName = "Demo Website #5",
                ClientUri = "http://website5.sso/",
                ClientSecrets = { new Secret("secret") },
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://website5.sso/Auth/SignInCallback" },
                PostLogoutRedirectUris = new List<string> { "http://website5.sso/" },
                LogoutUri = "http://website5.sso/Home/OidcSignOut",
                LogoutSessionRequired = true,
                AuthorizationCodeLifetime = 120,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Roles,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.Email,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = true,
                AllowRememberConsent = true
            },
            new Client
            {
                ClientId = "website6",
                ClientName = "Demo Website #6",
                ClientUri = "http://website6.sso/",
                ClientSecrets = { new Secret("secret") },
                Flow = Flows.AuthorizationCode,
                RedirectUris = new List<string> { "http://website6.sso/Auth/SignInCallback" },
                PostLogoutRedirectUris = new List<string> { "http://website6.sso/" },
                LogoutUri = "http://website6.sso/Home/OidcSignOut",
                LogoutSessionRequired = true,
                AuthorizationCodeLifetime = 120,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.Email,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = true,
                AllowRememberConsent = true,
            },

            #endregion

            #region Demos

            new Client
            {
                ClientId = "websitepracuj",
                ClientName = "Pracuj.pl",
                ClientUri = "http://website-pracuj.sso/",
                ClientSecrets = { new Secret("secret"), new Secret("us-secret") { Type = "universal_signin" } },
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://website-pracuj.sso/Auth/OidcSignInCallback" },
                PostLogoutRedirectUris = new List<string> { "http://website-pracuj.sso/" },
                LogoutUri = "http://website-pracuj.sso/Auth/OidcSignOut",
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.Email,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy", "api_offers"
                },
                RequireConsent = false,

                // Konfiguracja dla trybu ClientCredentials
                AllowClientCredentialsOnly = true,
                AlwaysSendClientClaims = false,
                PrefixClientClaims = false,
                Claims =
                {
                    new Claim("api_offers:read", "allow")
                }
            },
            new Client
            {
                ClientId = "websitepracuj_us",
                ClientSecrets = { new Secret("secret"), new Secret("us-secret") { Type = "universal_signin" } },
                Flow = Flows.Custom,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.Email,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy", "api_offers"
                },
                AllowedCustomGrantTypes = { "universal_signin" },
                AlwaysSendClientClaims = false,
                PrefixClientClaims = false,
                Claims =
                {
                    new Claim("api_offers:read", "allow")
                }
            },
            new Client
            {
                ClientId = "websitecv",
                ClientName = "Kreator CV",
                ClientUri = "http://website-cv.sso/",
                ClientSecrets = { new Secret("secret"), new Secret("us-secret") { Type = "universal_signin" } },
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://website-cv.sso/Auth/OidcSignInCallback" },
                PostLogoutRedirectUris = new List<string> { "http://website-cv.sso/" },
                LogoutUri = "http://website-cv.sso/Auth/OidcSignOut",
                RequireSignOutPrompt = true,
                AllowedScopes = {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                RequireConsent = false,

                // Konfiguracja dla trybu ClientCredentials
                AllowClientCredentialsOnly = true,
                AlwaysSendClientClaims = false,
                Claims =
                {
                    // empty
                }
            },
            new Client
            {
                ClientId = "websitecv_us",
                ClientSecrets = { new Secret("secret"), new Secret("us-secret") { Type = "universal_signin" } },
                Flow = Flows.Custom,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                AllowedCustomGrantTypes = { "universal_signin" },
                AlwaysSendClientClaims = false,
                PrefixClientClaims = false,
                Claims =
                {
                    // empty
                }
            },
            new Client
            {
                ClientId = "websitepracodawcy",
                ClientName = "Profile pracodawców",
                ClientUri = "http://website-pracodawcy.sso/",
                ClientSecrets = { new Secret("secret"), new Secret("us-secret") { Type = "universal_signin" } },
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://website-pracodawcy.sso/Auth/OidcSignInCallback" },
                PostLogoutRedirectUris = new List<string> { "http://website-pracodawcy.sso/" },
                LogoutUri = "http://website-pracodawcy.sso/Auth/OidcSignOut",
                RequireSignOutPrompt = true,
                AllowedScopes = {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                RequireConsent = false,

                // Konfiguracja dla trybu ClientCredentials
                AllowClientCredentialsOnly = true,
                AlwaysSendClientClaims = false,
                Claims =
                {
                    // empty
                }
            },
            new Client
            {
                ClientId = "websitepracodawcy_us",
                ClientSecrets = { new Secret("secret"), new Secret("us-secret") { Type = "universal_signin" } },
                Flow = Flows.Custom,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                AllowedCustomGrantTypes = { "universal_signin" },
                AlwaysSendClientClaims = false,
                PrefixClientClaims = false,
                Claims =
                {
                    // empty
                }
            },

            #endregion

            #region Shared Websites
            
            new Client
            {
                ClientId = "websiteshareda",
                ClientName = "WebSite Shared A",
                ClientUri = "http://website-a.shared.sso.com/",
                Flow = Flows.Implicit,
                RedirectUris = new List<string> { "http://website-a.shared.sso.com/" },
                PostLogoutRedirectUris = new List<string> { "http://website-a.shared.sso.com/" },
                LogoutUri = "http://website-a.shared.sso.com/Home/OidcSignOut",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile
                },
                RequireConsent = false,
                AllowRememberConsent = true,
            },
            new Client
            {
                ClientId = "websitesharedb",
                ClientName = "WebSite Shared B",
                ClientUri = "http://website-b.shared.sso.com/",
                Flow = Flows.Implicit,
                RedirectUris = new List<string> { "http://website-b.shared.sso.com/" },
                PostLogoutRedirectUris = new List<string> { "http://website-b.shared.sso.com/" },
                LogoutUri = "http://website-b.shared.sso.com/Home/OidcSignOut",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                RequireSignOutPrompt = true,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Profile
                },
                RequireConsent = false,
                AllowRememberConsent = true,
            },

            #endregion

            #region Actual Websites
            
            new Client
            {
                ClientId = "website_zarobki_eldorado",
                ClientSecrets = { new Secret("secret") },
                ClientName = "Zarobki Pracuj.pl",
                ClientUri = "http://localhost:3380/",
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://localhost:3380/signin-oidc" },
                PostLogoutRedirectUris = new List<string> { "http://localhost:3380/" },
                LogoutUri = "http://localhost:3380/Home/OidcSignOut",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AuthorizationCodeLifetime = 10,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                PrefixClientClaims = false,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Roles,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = false,
                AllowRememberConsent = true,
            },
            new Client
            {
                ClientId = "website_zarobki_b2c_frontend",
                ClientSecrets = { new Secret("secret") },
                ClientName = "Zarobki Pracuj.pl",
                ClientUri = "http://localhost:8070/app.php/r/",
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://localhost:8070/app.php/r/oidc-signin", "http://localhost:8070/app_dev.php/r/oidc-signin" },
                PostLogoutRedirectUris = new List<string> { "http://localhost:8070/app.php/r/", "http://localhost:8070/app_dev.php/r/" },
                LogoutUri = "http://localhost:8070/app_dev.php/r/oidc-signout",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AuthorizationCodeLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                PrefixClientClaims = false,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Roles,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy",
                    "website_zarobki_b2c_frontend"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = false,
                AllowRememberConsent = true
            },
            new Client
            {
                ClientId = "website_pracodawcy_frontend",
                ClientSecrets = { new Secret("secret") },
                ClientName = "Pracodawcy Pracuj.pl",
                ClientUri = "http://localhost:8050/",
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://localhost:8050/app.php/oidc-signin", "http://localhost:8050/app_dev.php/oidc-signin" },
                PostLogoutRedirectUris = new List<string> { "http://localhost:8050/app.php/", "http://localhost:8050/app_dev.php/" },
                LogoutUri = "http://localhost:8050/app_dev.php/oidc-signout",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AuthorizationCodeLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                PrefixClientClaims = false,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Roles,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy",
                    "website_pracodawcy_frontend"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = false,
                AllowRememberConsent = true
            },
            new Client
            {
                ClientId = "website_cv_frontend",
                ClientSecrets = { new Secret("secret") },
                ClientName = "CV.Pracuj.pl",
                ClientUri = "http://localhost:8060/",
                Flow = Flows.Hybrid,
                RedirectUris = new List<string> { "http://localhost:8060/app.php/oidc-signin", "http://localhost:8060/app_dev.php/oidc-signin" },
                PostLogoutRedirectUris = new List<string> { "http://localhost:8060/app.php/", "http://localhost:8060/app_dev.php/" },
                LogoutUri = "http://localhost:8060/app_dev.php/oidc-signout",
                LogoutSessionRequired = true,
                IdentityTokenLifetime = 120,
                AccessTokenLifetime = 120,
                AuthorizationCodeLifetime = 120,
                AccessTokenType = AccessTokenType.Jwt,
                RequireSignOutPrompt = true,
                PrefixClientClaims = false,
                AllowedScopes =
                {
                    Constants.StandardScopes.OpenId,
                    Constants.StandardScopes.Roles,
                    Constants.StandardScopes.Profile,
                    Constants.StandardScopes.OfflineAccess,
                    "dummy",
                    "website_cv_frontend"
                },
                AlwaysSendClientClaims = true,
                RequireConsent = false,
                AllowRememberConsent = true
            }

            #endregion
        };

        private static IEnumerable<Scope> Scopes => new List<Scope>
        {
            StandardScopes.OpenId,
            StandardScopes.RolesAlwaysInclude,
            StandardScopes.OfflineAccess,
            StandardScopes.EmailAlwaysInclude,
            StandardScopes.ProfileAlwaysInclude,
            new Scope
            {
                Name = "api_cv_profile",
                Type = ScopeType.Resource,
                Claims =
                {
                    new ScopeClaim("api_cv_profile:read", true),
                    new ScopeClaim("api_cv_profile:write", true)
                }
            },
            new Scope
            {
                Name = "api_offers",
                Type = ScopeType.Resource,
                Claims =
                {
                    new ScopeClaim("api_offers:read", true),
                    new ScopeClaim("api_offers:write", true)
                }
            },
            new Scope
            {
                Name = "api_filestore",
                Type = ScopeType.Resource,
                Claims =
                {
                    new ScopeClaim("api_filestore:read", true),
                    new ScopeClaim("api_filestore:unrestricted_read", true),
                    new ScopeClaim("api_filestore:store", true)
                }
            },
            new Scope
            {
                Name = "dummy",
                Type = ScopeType.Resource,
                AllowUnrestrictedIntrospection = true
            },
            new Scope
            {
                Name = "website_pracodawcy_frontend",
                AllowUnrestrictedIntrospection = true,
                ScopeSecrets = { new Secret("secret") },
                ShowInDiscoveryDocument = false
            },
            new Scope
            {
                Name = "website_zarobki_b2c_frontend",
                AllowUnrestrictedIntrospection = true,
                ScopeSecrets = { new Secret("secret") },
                ShowInDiscoveryDocument = false
            },
            new Scope
            {
                Name = "website_cv_frontend",
                AllowUnrestrictedIntrospection = true,
                ScopeSecrets = { new Secret("secret") },
                ShowInDiscoveryDocument = false
            }
        };

        private static readonly List<InMemoryUser> PracujUsers = new List<InMemoryUser>
        {
            new InMemoryUser
            {
                Username = "bob",
                Password = "pwd",
                Subject = "21370331",
                Claims = new[]
                {
                    new Claim(Constants.ClaimTypes.GivenName, "Bob"),
                    new Claim(Constants.ClaimTypes.FamilyName, "Smith"),
                    new Claim(Constants.ClaimTypes.Name, "Bob Smith"),
                    new Claim(Constants.ClaimTypes.Email, "bob@demo.sso"),
                    new Claim(Constants.ClaimTypes.Role, "pracuj_user")
                }
            },
            new InMemoryUser
            {
                Username = "alice",
                Password = "pwd",
                Subject = "2",
                Claims = new[]
                {
                    new Claim(Constants.ClaimTypes.GivenName, "Alice"),
                    new Claim(Constants.ClaimTypes.FamilyName, "Smith"),
                    new Claim(Constants.ClaimTypes.Name, "Alice Smith"),
                    new Claim(Constants.ClaimTypes.Email, "alice@demo.sso"),
                    new Claim(Constants.ClaimTypes.Role, "pracuj_user")
                }
            },
            new InMemoryUser
            {
                Username = "joe",
                Password = "pwd",
                Subject = "3",
                Claims = new[]
                {
                    new Claim(Constants.ClaimTypes.GivenName, "Joe"),
                    new Claim(Constants.ClaimTypes.FamilyName, "Doe"),
                    new Claim(Constants.ClaimTypes.Name, "Joe Doe"),
                    new Claim(Constants.ClaimTypes.Email, "joe@demo.sso"),
                    new Claim(Constants.ClaimTypes.Role, "pracuj_user")
                }
            },
            new InMemoryUser
            {
                Username = "prac",
                Password = "pwd",
                Subject = "4",
                Claims = new[]
                {
                    new Claim(Constants.ClaimTypes.GivenName, "Prac"),
                    new Claim(Constants.ClaimTypes.FamilyName, "Usr"),
                    new Claim(Constants.ClaimTypes.Name, "Prac Usr"),
                    new Claim(Constants.ClaimTypes.Email, "prac.usr@demo.sso"),
                    new Claim(Constants.ClaimTypes.Role, "pracuj_user")
                }
            }
        };

        private static readonly List<InMemoryUser> StrefaUsers = new List<InMemoryUser>
        {
            new InMemoryUser
            {
                Username = "str",
                Password = "pwd",
                Subject = "100",
                Claims = new[]
                {
                    new Claim(Constants.ClaimTypes.GivenName, "Str"),
                    new Claim(Constants.ClaimTypes.FamilyName, "Usr"),
                    new Claim(Constants.ClaimTypes.Name, "Str Usr"),
                    new Claim(Constants.ClaimTypes.Email, "str.usr@demo.sso"),
                    new Claim(Constants.ClaimTypes.Role, "strefa_user")
                }
            },
            new InMemoryUser
            {
                Username = "demoats",
                Password = "pwd",
                Subject = "101",
                Claims = new[]
                {
                    new Claim(Constants.ClaimTypes.GivenName, "Demo"),
                    new Claim(Constants.ClaimTypes.FamilyName, "Demo"),
                    new Claim(Constants.ClaimTypes.Name, "Demo Demo"),
                    new Claim(Constants.ClaimTypes.Email, "demoats@pracuj.pl"),
                    new Claim(Constants.ClaimTypes.Role, "strefa_user")
                }
            }
        };

        public void Configuration(IAppBuilder app)
        {
            var dvso = new DefaultViewServiceOptions();
            dvso.Stylesheets.Add("~/Content/custom.css");
            dvso.Scripts.Add("~/Scripts/custom.js");


            var isf = new IdentityServerServiceFactory()
                .UseInMemoryClients(Clients)
                .UseInMemoryScopes(Scopes);
//                .UseInMemoryUsers(Users);

            isf.ConfigureDefaultViewService(dvso);

            isf.UserService = new Registration<IUserService>(ctx => new CustomUserService(PracujUsers));
//            isf.UserService = new Registration<IUserService>(ctx =>
//            {
//                var userServices = new Dictionary<string, IUserService>
//                {
//                    { Tenants.Pracuj, new CustomUserService(PracujUsers) },
//                    { Tenants.Strefa, new CustomUserService(StrefaUsers) }
//                };
//
//                return new TenantAwareUserService(userServices, Tenants.Pracuj);
//            });

            isf.SecretValidators = new List<Registration<ISecretValidator>> { new Registration<ISecretValidator,PlainTextSharedSecretValidator>() };
//            isf.RefreshTokenStore = new Registration<IRefreshTokenStore, InMemoryRefreshTokenStore>();
//            isf.ConsentStore = new Registration<IConsentStore, InMemoryConsentStore>();
//            isf.AuthorizationCodeStore = new Registration<IAuthorizationCodeStore, InMemoryAuthorizationCodeStore>();
//            isf.TokenHandleStore = new Registration<ITokenHandleStore, InMemoryTokenHandleStore>();

            isf.CustomGrantValidators.Add(new Registration<ICustomGrantValidator, DelegationGrantValidator>());
            isf.CustomGrantValidators.Add(new Registration<ICustomGrantValidator, UniversalSignInGrantValidator>());
            isf.CustomTokenResponseGenerator = new Registration<ICustomTokenResponseGenerator, CustomTokenResponseGenerator>();
            isf.EventService = new Registration<IEventService, CustomEventService>();

            var iso = new IdentityServerOptions
            {
                SiteName = "SSO Demo",
                SigningCertificate = new X509Certificate2(File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "abc.pfx")), "qwertyqaz"),
                RequireSsl = false,
                Factory = isf,
                AuthenticationOptions = new AuthenticationOptions
                {

                    IdentityProviders = ConfigureIdentityProviders,
                    EnablePostSignOutAutoRedirect = false,
                    LoginPageLinks = new[]
                    {
                        new LoginPageLink
                        {
                            Href = "https://pracuj.pl/zaloz-konto",
                            Type = "abc-type",
                            Text = "rejestracja"
                        }
                    }
                },
                EventsOptions = new EventsOptions
                {
                    RaiseSuccessEvents = true,
                    RaiseErrorEvents = true,
                    RaiseFailureEvents = true,
                    RaiseInformationEvents = true
                }
            };

            app.UseIdentityServer(iso);

            //  niestety wygląda na to, że ani FB, ani Google, ani Twitter nie wspierają rozporoszonego wylogowywania

//            app.Map("/federated-signout", cleanup =>
//            {
//                cleanup.Run(async ctx =>
//                {
//                    await ctx.Environment.ProcessFederatedSignoutAsync();
//                });
//            });
        }

        private static void ConfigureIdentityProviders(IAppBuilder app, string signInAsType)
        {
            app.UseTwitterAuthentication(new TwitterAuthenticationOptions
            {
                AuthenticationType = "Twitter",
                Caption = "Twitter",
                SignInAsAuthenticationType = signInAsType,
                ConsumerKey = "gcQ8mv2ZikfRoqjY7KzM4YQ6r",
                ConsumerSecret = "C6k7Ez2LlcST8uJc5POf8pLcZX4NqhTy7CvQnmPM3WdApCJZ6M"
            });

            app.UseFacebookAuthentication(new FacebookAuthenticationOptions
            {
                AuthenticationType = "Facebook",
                Caption = "Facebook",
                SignInAsAuthenticationType = signInAsType,
                AppId = "1330899903706130",
                AppSecret = "60f5eee8dc855c504d95d471ca16c582"
            });

            app.UseGoogleAuthentication(new GoogleOAuth2AuthenticationOptions
            {
                AuthenticationType = "Google",
                Caption = "Google",
                SignInAsAuthenticationType = signInAsType,
                ClientId = "952075585362-9ld90ptus3mitjrdpn3svc8siuk3b8vp.apps.googleusercontent.com",
                ClientSecret = "a6OO-wq8KPe4PJ9kFoY0-788"
            });
        }

        public class CustomEventService : DefaultEventService
        {
            public override async Task RaiseAsync<T>(Event<T> evt)
            {
                await base.RaiseAsync(evt);

                if (evt.Id == EventConstants.Ids.EndpointSuccess)
                {
                    HttpContext.Current.GetOwinContext().Response.Cookies.Append("idsrv.frontchannelsso", "xxxx", new Microsoft.Owin.CookieOptions
                    {
                        Domain = ".sso.com",
                        Expires = DateTime.UtcNow.AddDays(2),
                        HttpOnly = true
                    });
                }

                if (evt.Id == EventConstants.Ids.Logout)
                {
                    HttpContext.Current.GetOwinContext().Response.Cookies.Append("idsrv.frontchannelsso", "xxxx", new Microsoft.Owin.CookieOptions
                    {
                        Domain = ".sso.com",
                        Expires = DateTime.UtcNow.AddYears(-1),
                        HttpOnly = true
                    });
                }
            }
        }
    }
}
