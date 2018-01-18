using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using NLog.Owin.Logging;
using Owin;

[assembly: OwinStartup(typeof(Website1.Web1Startup))]

namespace Website1
{
    public class Web1Startup
    {
        public void Configuration(IAppBuilder app)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseNLog();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                Authority = "http://auth.sso.com",
                ClientId = "website1",
                RedirectUri = "http://website1.sso/",
                ResponseType = "id_token token",
                SignInAsAuthenticationType = "Cookies",
                PostLogoutRedirectUri = "http://website1.sso/",
                Scope = "openid profile dummy",
                UseTokenLifetime = false,
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = n =>
                    {
                        var ci = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType, "name", "role");

                        ci.AddClaims(n.AuthenticationTicket.Identity.Claims);

                        // keep for logout
                        ci.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));
                        ci.AddClaim(new Claim("session_state", n.ProtocolMessage.SessionState));

                        // keep for api usage
                        ci.AddClaim(new Claim("access_token", n.ProtocolMessage.AccessToken));

                        // keep track of access token expiration
                        ci.AddClaim(new Claim("_tmp_expires_at", DateTimeOffset.Now.AddSeconds(int.Parse(n.ProtocolMessage.ExpiresIn)).ToString()));
                        
                        n.AuthenticationTicket = new AuthenticationTicket(ci, n.AuthenticationTicket.Properties);

                        return Task.CompletedTask;
                    },
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                        {
                            n.ProtocolMessage.IdTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token")?.Value;
                        }

                        return Task.CompletedTask;
                    }
                }
            });
        }
    }
}
