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

[assembly: OwinStartup(typeof(WebsitePracodawcy.WebsitePracodawcyStartup))]

namespace WebsitePracodawcy
{
    public class WebsitePracodawcyStartup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            const string scope = "openid profile offline_access dummy";

            var tvp = new TokenValidationParameters
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role,
                ValidAudiences = new[] { "websitepracodawcy", "websitepracodawcy_us" }
            };

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitepracodawcy",
                ClientSecret = "secret",
                ResponseType = "code id_token",
                Scope = scope,
                RedirectUri = "http://website-pracodawcy.sso/Auth/OidcSignInCallback",
                PostLogoutRedirectUri = "http://website-pracodawcy.sso/",
                TokenValidationParameters = tvp,
                UseTokenLifetime = false,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = OpenIdConnectAuthenticationEventsHandler.HandleAuthorizationCodeReceived(us =>
                    {
                        // TODO raczej jakoś ładniej można by to zapewne ogarnąć niż poprzez sesję
                        HttpContext.Current.Session["universal_signin"] = us;
                    }),
                    RedirectToIdentityProvider = OpenIdConnectAuthenticationEventsHandler.HandleRedirectToIdentityProvider
                }
            });

            app.UseRefreshToken(new RefreshTokenOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitepracodawcy",
                ClientSecret = "secret",
                TokenValidationParameters = tvp
            });

            app.UseUniversalSignInTokenAuthentication(new UniversalSignInTokenAuthnticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitepracodawcy_us",
                ClientSecret = "secret",
                Scope = scope,
                TokenValidationParameters = tvp
            });
        }
    }
}
