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
                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,
                ValidAudiences = new [] { "websitepracuj", "websitepracuj_us" }
            };

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitepracuj",
                ClientSecret = "secret",
                ResponseType = "code id_token",
                Scope = scope,
                RedirectUri = "http://website-pracuj.sso/Auth/OidcSignInCallback",
                PostLogoutRedirectUri = "http://website-pracuj.sso/",
                TokenValidationParameters = tvp,
                UseTokenLifetime = false,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = OpenIdConnectAuthenticationEventsHandler.HandleAuthorizationCodeReceived(us =>
                    {
                        // TODO raczej jakoś ładniej można by to zapewne ogarnąć niż poprzez sesję
                        HttpContext.Current.Session["universal_signin"] = us;
                    }),
                    RedirectToIdentityProvider = OpenIdConnectAuthenticationEventsHandler.HandleRedirectToIdentityProvider()
                }
            });

            app.UseRefreshToken(new RefreshTokenOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitepracuj",
                ClientSecret = "secret",
                TokenValidationParameters = tvp
            });

            app.UseUniversalSignInTokenAuthentication(new UniversalSignInTokenAuthnticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitepracuj_us",
                ClientSecret = "secret",
                Scope = scope,
                TokenValidationParameters = tvp
            });
        }
    }
}