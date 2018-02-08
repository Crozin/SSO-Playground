using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using NLog.Owin.Logging;
using Owin;
using SharedNet;

[assembly: OwinStartup(typeof(Website3.Web3Startup))]

namespace Website3
{
    public class Web3Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            const string scope = "openid roles profile";

            var tvp = new TokenValidationParameters
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                NameClaimType = "name",
                RoleClaimType = "role"
            };

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = CookieAuthenticationDefaults.AuthenticationType
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "website3",
                ClientSecret = "secret",
                RedirectUri = "http://website3.sso/",
                ResponseType = "code id_token",
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                Scope = scope,
                PostLogoutRedirectUri = "http://website3.sso/",
                TokenValidationParameters = tvp,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    MessageReceived = n =>
                    { 
                        // available: code, state, session_state
                        return Task.CompletedTask;
                    },
                    SecurityTokenReceived = n =>
                    { 
                        // available: code, id_token, scope, state, session_state
                        return Task.CompletedTask;
                    },
                    AuthorizationCodeReceived = OpenIdConnectAuthenticationEventsHandler.HandleAuthorizationCodeReceived(null),
                    SecurityTokenValidated = n =>
                    { 
                        // available: code, id_token, scope, state, session_state, nonce
                        return Task.CompletedTask;
                    },
                    RedirectToIdentityProvider = OpenIdConnectAuthenticationEventsHandler.HandleRedirectToIdentityProvider("tenant:strefa abc:def")
                }
            });
        }
    }
}
