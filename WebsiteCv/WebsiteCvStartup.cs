using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using IdentityModel;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using NLog;
using NLog.Owin.Logging;
using Owin;
using SharedNet;

[assembly: OwinStartup(typeof(WebsiteCv.WebsiteCvStartup))]

namespace WebsiteCv
{
    public class WebsiteCvStartup
    {
        private static readonly Logger Logger = LogManager.GetCurrentClassLogger();

        public void Configuration(IAppBuilder app)
        {

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            const string scope = "openid profile offline_access dummy";

            var tvp = new TokenValidationParameters
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                NameClaimType = "given_name",
                RoleClaimType = JwtClaimTypes.Role,
                ValidAudiences = new[] { "cv_usi_website_dev", "cv_usi_website_us_dev" }
            };

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "https://auth-sso-dev.gp.local",
//                Authority = "https://localhost/IdentityServer",
                ClientId = "cv_usi_website_dev",
                ClientSecret = "secret",
                ResponseType = "code id_token",
                Scope = scope,
                RedirectUri = "https://cv-usi.gp.local/Auth/OidcSignInCallback",
                PostLogoutRedirectUri = "https://cv-usi.gp.local/",
                TokenValidationParameters = tvp,
                UseTokenLifetime = false,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = OpenIdConnectAuthenticationEventsHandler.HandleAuthorizationCodeReceived(us =>
                    {
                        Logger.Info("RECEIVED USI codes: " + string.Join(", ", us.Select(u => u.TargetUri).ToArray()));

                        // TODO raczej jakoś ładniej można by to zapewne ogarnąć niż poprzez sesję
                        HttpContext.Current.Session["universal_sign_in"] = us;
                    }),
                    RedirectToIdentityProvider = OpenIdConnectAuthenticationEventsHandler.HandleRedirectToIdentityProvider()
                },
                BackchannelCertificateValidator = new DummyCertificateValidator()
            });

            app.UseRefreshToken(new RefreshTokenOptions
            {
                                Authority = "https://auth-sso-dev.gp.local",
//                Authority = "https://localhost/IdentityServer",
                ClientId = "cv_usi_website_dev",
                ClientSecret = "secret",
                TokenValidationParameters = tvp,
                BackchannelCertificateValidator = new DummyCertificateValidator()
            });

            app.UseUniversalSignInTokenAuthentication(new UniversalSignInTokenAuthnticationOptions
            {
                                Authority = "https://auth-sso-dev.gp.local",
//                Authority = "https://localhost/IdentityServer",
                ClientId = "cv_usi_website_us_dev",
                ClientSecret = "secret",
                Scope = scope,
                TokenValidationParameters = tvp,
                BackchannelCertificateValidator = new DummyCertificateValidator()
            });
        }
    }
}
