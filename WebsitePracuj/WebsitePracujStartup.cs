using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Web;
using IdentityModel;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using NLog.Owin.Logging;
using Owin;
using SharedNet;

[assembly: OwinStartup(typeof(WebsitePracuj.WebsitePracujStartup))]

namespace WebsitePracuj
{
    public class WebsitePracujStartup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            const string scope = "openid profile email offline_access dummy";

            var tvp = new TokenValidationParameters
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                NameClaimType = "given_name",
                RoleClaimType = JwtClaimTypes.Role,
                ValidAudiences = new [] { "pracuj_usi_website_dev", "pracuj_usi_website_us_dev" }
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
                ClientId = "pracuj_usi_website_dev",
                ClientSecret = "secret",
                ResponseType = "code id_token",
                Scope = scope,
                RedirectUri = "https://pracuj-usi.gp.local/Auth/OidcSignInCallback",
                PostLogoutRedirectUri = "https://pracuj-usi.gp.local/",
                TokenValidationParameters = tvp,
                UseTokenLifetime = false,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = OpenIdConnectAuthenticationEventsHandler.HandleAuthorizationCodeReceived(us =>
                    {
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
                ClientId = "pracuj_usi_website_dev",
                ClientSecret = "secret",
                TokenValidationParameters = tvp,
                BackchannelCertificateValidator = new DummyCertificateValidator()
            });

            app.UseUniversalSignInTokenAuthentication(new UniversalSignInTokenAuthnticationOptions
            {
                                Authority = "https://auth-sso-dev.gp.local",
//                Authority = "https://localhost/IdentityServer",
                ClientId = "pracuj_usi_website_us_dev",
                ClientSecret = "secret",
                Scope = scope,
                TokenValidationParameters = tvp,
                BackchannelCertificateValidator = new DummyCertificateValidator()
            });
        }
    }
}