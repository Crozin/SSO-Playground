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

[assembly: OwinStartup(typeof(WebsiteCv.WebsiteCvStartup))]

namespace WebsiteCv
{
    public class WebsiteCvStartup
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
                ValidAudiences = new[] { "websitecv", "websitecv_us" }
            };

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitecv",
                ClientSecret = "secret",
                ResponseType = "code id_token",
                Scope = scope,
                RedirectUri = "http://website-cv.sso/Auth/OidcSignInCallback",
                PostLogoutRedirectUri = "http://website-cv.sso/",
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
                ClientId = "websitecv",
                ClientSecret = "secret",
                TokenValidationParameters = tvp
            });

            app.UseUniversalSignInTokenAuthentication(new UniversalSignInTokenAuthnticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "websitecv_us",
                ClientSecret = "secret",
                Scope = scope,
                TokenValidationParameters = tvp
            });
        }
    }
}
